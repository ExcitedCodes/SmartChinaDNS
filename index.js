const dns = require("dns2");
const url = require("url");
const utils = require("./utils");
const { execFile } = require('child_process');
const CIDRMatcher = require('cidr-matcher');

var CDNIPRange, CHNRoute, BlackList, WhiteList;

var config;
try {
    config = require("./config");
} catch {
    console.error('未找到配置文件或配置有误, 请参考 config.js.example 创建一个可用的配置文件');
    return;
}

/**
 * 初始化配置
 */
async function init() {
    const timeStart = new Date().getTime();

    console.log("Loading CDN IP Range...");
    CDNIPRange = new CIDRMatcher(await utils.LoadIP(config.CDNIPRange));

    console.log("Loading China Route...");
    CHNRoute = new CIDRMatcher(await utils.LoadIP(config.CHNRoute));

    console.log("Loading Black List...");
    BlackList = new utils.DomainMatcher();
    await BlackList.LoadFromFile(config.BlackList);

    console.log("Loading White List...");
    WhiteList = new utils.DomainMatcher();
    await WhiteList.LoadFromFile(config.WhiteList);

    utils.loadServer(config.TrustDNS);
    utils.loadServer(config.ChinaDNS);

    console.log(`Configuration loaded in ${(new Date().getTime() - timeStart)}ms`);

    dns.createServer(handleQuery).listen({
        port: url.parse(config.Listen).port,
        address: url.parse(config.Listen).hostname,
        exclusive: config.Exclusive
    }, () => {
        console.log("SmartChinaDNS is ready on " + config.Listen);
    });
}

/**
 * 这是魔法
 * @param {*} request 魔法
 * @param {*} response 魔法
 * @param {*} trusted 魔法
 * @param {*} send 魔法
 */
function performQuery(request, response, trusted, send) {
    const key = trusted ? 'trusted' : 'china';
    const dnsKey = trusted ? 'TrustDNS' : 'ChinaDNS';
    utils.createQuery(config[dnsKey], config.Timeout, request).then((answer) => {
        response[key] = dns.Packet.parse(answer.toBuffer());
        judgeResult(response, trusted, send);
    }).catch((reason) => {
        console.error(`${dnsKey} error: ${reason}`);
        response[key] = utils.emptyPacket(request);
        judgeResult(response, trusted, send);
    });
}

/**
 * 处理监听的 DNS 服务器收到的查询请求
 * @param {*} request DNS request packet
 * @param {*} send 
 * @param {*} rinfo Remote info
 */
async function handleQuery(request, send, rinfo) {
    rinfo.timeStart = new Date();

    // Discard all unsupported stuffs
    request.header.arcount = 0;
    request.additionals = [];

    if (request.questions.length == 0) {
        send(utils.emptyPacket(request));
        utils.GenerateLog(request, rinfo);
        return;
    }

    // 注意: 几乎所有实现都是多 questions 不友好的
    for (const q of request.questions) {
        console.log(`Query[${utils.getKeyByValue(dns.Packet.TYPE, q.type)}] ${q.name} from ${rinfo.address}`);
    }

    /*
    if (request.questions[0].type == dns.Packet.TYPE.PTR) {
        send(utils.emptyPacket(request));
        utils.GenerateLog(request, rinfo);
        return;
    }
    */


    // IPv6 AAAA记录过滤，直接对请求返回空即可
    if (request.questions[0].type == dns.Packet.TYPE.AAAA) {
        switch (config.FilterIPv6) {
            case 'all':
                send(utils.emptyPacket(request));
                utils.GenerateLog(request, rinfo, "(Blocked All AAAA Request)");
                return;
            case 'china':
                if (!WhiteList.contains(request.questions[0].name)) {
                    send(utils.emptyPacket(request));
                    utils.GenerateLog(request, rinfo, "(Blocked Non-Chinese Domain AAAA Request)");
                    return;
                }
                break;
            case 'foreign':
                if (WhiteList.contains(request.questions[0].name)) {
                    send(utils.emptyPacket(request));
                    utils.GenerateLog(request, rinfo, "(Blocked Chinese Domain AAAA Request)");
                    return;
                }
                break;
        }
    }

    // 虽然上面for了，但是其实我搜索了一下没有人会在一个DNS包里带俩questions
    // 所以直接取第一个进行判断黑白名单.
    if (BlackList.contains(request.questions[0].name)) {
        // 在黑名单中
        console.log(`${request.questions[0].name} match BlackList, forwarding to TrustDNS`);
        const TrustAnswer = await utils.createQuery(config.TrustDNS, config.Timeout, request)
            .catch((reason) => {
                console.error(`TrustDNS error: ${reason}`);
                return utils.emptyPacket(request);
            });
        send(TrustAnswer);
        utils.GenerateLog(TrustAnswer, rinfo, "(TrustDNS)");
        for (const q of TrustAnswer.answers) {
            if (q.type == dns.Packet.TYPE.A) {
                addIPSet(q.address, TrustAnswer.questions[0].name, config.IpsetToAdd);
            }
        }
        return;
    }

    if (WhiteList.contains(request.questions[0].name)) {
        // 在白名单中
        console.log(`${request.questions[0].name} match WhiteList, forwarding to ChinaDNS`);
        const ChinaAnswer = await utils.createQuery(config.ChinaDNS, config.Timeout, request)
            .catch((reason) => {
                console.error(`ChinaDNS error: ${reason}`);
                return utils.emptyPacket(request);
            });
        send(ChinaAnswer);
        utils.GenerateLog(ChinaAnswer, rinfo, "(ChinaDNS)");
        return;
    }

    var response = {
        sent: false,
        rinfo,
        china: null,
        trusted: null
    };
    performQuery(request, response, true, send);
    performQuery(request, response, false, send);
    //接下来的逻辑在 judgeResult，它会负责发 Response
}

/**
 * 检测两个DNS的结果是否一致, 不一致则添加 IPSet
 * @param {*} anotherResult 另一 DNS 的返回结果
 * @param {*} currentAnswer 当前 DNS 返回 IP 列表
 */
function matchResult(anotherResult, currentAnswer) {
    let same = false;
    for (const c of anotherResult.answers) {
        if (c.type == dns.Packet.TYPE.A && currentAnswer.includes(c.address)) {
            same = true;
        }
    }
    for (const q of currentAnswer) {
        // 被污染时 same = false 则直接添加
        // 未被污染时 same = true 进行RST检测
        addIPSet(q, anotherResult.questions[0].name, config.IpsetToAdd, same);
    }
}

/**
 * 核心判断逻辑
 * @param {*} state 存储当前请求状态的对象
 * @param {*} trusted 是否来自可信 DNS
 * @param {*} _send 回复 DNS 请求的回调函数
 */
function judgeResult(state, trusted, _send) {
    if (state.sent) {
        return;
    }
    const send = (trusted) => {
        const answer = trusted ? state.trusted : state.china;
        _send(answer);
        state.sent = true;
        utils.GenerateLog(answer, state.rinfo, trusted ? '(TrustDNS)' : '(ChinaDNS)');
    };
    const ChinaAnswer = state.china;
    const TrustAnswer = state.trusted;
    if (trusted) {
        // 触发Judge的是可信DNS返回
        if (TrustAnswer.answers.length == 0) {
            if (ChinaAnswer && ChinaAnswer.answers.length == 0) { // 两个DNS都没查询到结果
                send(true);
            }
            // 暂时只是可信DNS没查到结果
            // 跳过 等中国DNS查询
            return;
        }
        let AnswerIP = [];
        for (const q of TrustAnswer.answers) {
            if (q.type == dns.Packet.TYPE.A) {
                AnswerIP.push(q.address);
            }
        }
        if (AnswerIP.length == 0) {
            // 不含IP地址，可能是其他类型记录
            // 直接返回
            send(true);
        } else if (CHNRoute.containsAny(AnswerIP)) {
            // 返回的包含中国IP
            // 直接返回
            send(true);
        } else if (CDNIPRange.containsAny(AnswerIP)) {
            // 返回的包含CDN IP
            // 需要进行RST检测
            send(true);
            for (const q of AnswerIP) {
                addIPSet(q, TrustAnswer.questions[0].name, config.IpsetToAdd, true);
            }
        } else if (ChinaAnswer) {
            // 中国DNS判断失败, 在等待可信DNS
            send(true);
            matchResult(ChinaAnswer, AnswerIP); // 比对两个DNS的返回结果
        }
        // 中国DNS还未回应
        // 等待中国DNS
    } else {
        // 触发Judge的是中国DNS返回
        if (ChinaAnswer.answers.length == 0) {
            if (TrustAnswer && TrustAnswer.answers.length == 0) { // 两个DNS都没查询到结果
                send(true);
            }
            // 暂时只是中国DNS没查到结果
            // 跳过 等可信DNS查询
            return;
        }
        let AnswerIP = [];
        for (const q of ChinaAnswer.answers) {
            if (q.type == dns.Packet.TYPE.A) {
                AnswerIP.push(q.address);
            }
        }
        if (AnswerIP.length == 0) {
            // 不含IP地址，可能是其他类型记录
            // 直接返回
            send(false);
        } else if (CHNRoute.containsAny(AnswerIP)) {
            // 返回的包含中国IP
            // 直接返回
            send(false);
        } else if (CDNIPRange.containsAny(AnswerIP)) {
            // 返回的包含CDN IP
            // 需要进行RST检测
            send(false);
            for (const q of AnswerIP) {
                addIPSet(q, ChinaAnswer.questions[0].name, config.IpsetToAdd, true);
            }
        } else if (TrustAnswer) {
            // 可信DNS在等待中国DNS
            if (TrustAnswer.answers.length != 0) {
                send(true);
                matchResult(TrustAnswer, AnswerIP); // 比对两个DNS的返回结果
            } else {
                // 可信DNS返回空，中国DNS有结果
                send(false);
            }
        }
        // 不符合以上情况
        // 等待可信DNS
    }
}

/**
 * 进行可选的 HTTP(S) RST 检测并添加被干扰的记录到 IPSet
 * @param {string} ip 要添加/检测的 IP
 * @param {string} host RST 检测时请求的 Hostname
 * @param {boolean} check 是否进行 RST 检测
 */
async function addIPSet(ip, host, setname, check = false) {
    if (check && config.AutoDetectRST) {
        console.log(`Performing HTTP(S) RST Check for ${host} on ${ip}`);
        const timeStart = new Date();
        if (!await utils.RSTCheck(host, ip)) {
            console.log(`${host} on ${ip} RST Check passed (responsed in ${(new Date() - timeStart)}ms)`);
            return;
        }
    }
    if (!setname) {
        return;
    }
    execFile('/usr/sbin/ipset', ['add', setname, ip], (err) => {
        if (err) {
            console.error(`An error occurred when adding ${ip} to the set ${setname}: ${err.message}`);
        } else {
            console.log(`${ip} was added to the set ${setname}`);
        }
    });
}

// Dirty Patching...
// 暂时Patch，将来补完支持（也许永远不会有）
// 只是为了不出现error log
dns.Packet.TYPE.WTF = 0; //我也不知道这是什么
dns.Packet.TYPE.OPT = 41;
dns.Packet.Resource.OPT =
    dns.Packet.Resource.WTF = {
        decode: function () {
            return this;
        },
        encode: function () {
            return this;
        }
    };

init();
