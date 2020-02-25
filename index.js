const dns = require("dns2");
const url = require("url");
const utils = require("./utils");
const { execFile } = require('child_process');
const CIDRMatcher = require('cidr-matcher');

var CDNIPRange, CHNRoute, BlackList, WhiteList;

let config;
try {
    config = require("./config");
} catch {
    console.error('未找到配置文件或配置有误, 请参考 config.js.example 创建一个可用的配置文件');
    return;
}

/**
 * 加载 DNS 服务器或对 DOH URL 进行预处理
 * 
 * 此函数将创建 config.DNS = require('dns')
 * 
 * @param {*} config 服务器配置对象
 */
function loadServer(config) {
    if (config.Type == "dns") {
        config.DNS = require('dns');
        config.DNS.setServers([config.Addr]);
    } else {
        config.URL += config.URL.lastIndexOf('?') === -1 ? '?' : '&';
    }
}

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

    loadServer(config.TrustDNS);
    loadServer(config.ChinaDNS);

    console.log(`Configuration loaded in ${(new Date().getTime() - timeStart)}ms`);

    dns.createServer(handleQuery).listen({
        port: url.parse(config.Listen).port,
        address: url.parse(config.Listen).hostname,
        exclusive: config.Exclusive
    }, () => {
        console.log("SmartChinaDNS is ready on " + config.Listen);
    });
}

function performQuery(config, timeout, packet) {
    if (config.Type == 'dns') {
        return utils.DNSRequest(config.DNS, packet)
            .catch((reason) => {
                console.error(`DNS Error occurred: ${reason}`);
                return utils.emptyPacket(packet);
            });
    } else {
        return utils.DoHRequest(config.URL, timeout, packet)
            .catch((reason) => {
                console.error(`DoH Error occurred: ${reason}`);
                return utils.emptyPacket(packet);
            });
    }
}

/**
 * 处理监听的 DNS 服务器收到的查询请求
 * @param {*} request DNS request packet
 * @param {*} send 
 * @param {*} rinfo Remote info
 */
async function handleQuery(request,send,rinfo){
    rinfo.timeStart = new Date().getTime();

    // Discard all unsupported stuffs
    request.header.arcount = 0;
    request.additionals = [];

    if (request.questions.length == 0) {
        send(utils.emptyPacket(request));
        utils.GenerateLog(request, rinfo);
        return;
    }
    
    for(q of request.questions) {
        console.log(`Query[${utils.getKeyByValue(dns.Packet.TYPE,q.type)}] ${q.name} from ${rinfo.address}`);
    }
    
    if(request.questions[0].type == dns.Packet.TYPE.PTR){
        send(utils.emptyPacket(request));
        utils.GenerateLog(request,rinfo);
        return;
    }

    // 虽然上面for了，但是其实我搜索了一下没有人会在一个DNS包里带俩questions
    // 所以直接取第一个进行判断黑白名单
    if(BlackList.contains(request.questions[0].name)) {
        // 在黑名单中
        console.log(`${request.questions[0].name} match BlackList, forwarding to TrustDNS`);
        const TrustAnswer = await performQuery(config.TrustDNS,config.Timeout,request);
        send(TrustAnswer);
        utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
        for(q of TrustAnswer.answers){
            if(q.type == dns.Packet.TYPE.A){
                AddIPSet(q.address,TrustAnswer.questions[0].name);
            }
        }
        return;
    }
    if(WhiteList.contains(request.questions[0].name)){
        // 在白名单中
        console.log(`${request.questions[0].name} match WhiteList, forwarding to ChinaDNS`);
        const ChinaAnswer = await performQuery(config.ChinaDNS,config.Timeout,request);
        send(ChinaAnswer);
        utils.GenerateLog(ChinaAnswer,rinfo,"(ChinaDNS)");
        return;
    }

    // 未判定域名
    var TrustAnswer, ChinaAnswer;
    performQuery(config.TrustDNS,config.Timeout,request).then((answer) => {
        TrustAnswer = dns.Packet.parse(answer.toBuffer());
        JudgeResult(TrustAnswer,ChinaAnswer,1,send,rinfo);
    });
    performQuery(config.ChinaDNS,config.Timeout,request).then((answer) => {
        ChinaAnswer = dns.Packet.parse(answer.toBuffer());
        JudgeResult(TrustAnswer,ChinaAnswer,2,send,rinfo);
    });
    setTimeout(() => {
        request = utils.emptyPacket(request);
        if(typeof ChinaAnswer == "undefined" && typeof TrustAnswer == "undefined"){
            send(request);
            console.log("Timeout exceeded, but none of the DNS Servers answered");
            utils.GenerateLog(request,rinfo);
            return;
        }
        if(typeof ChinaAnswer == "undefined"){
            ChinaAnswer = request;
            console.log("Timeout exceeded, giving up ChinaDNS");
            JudgeResult(TrustAnswer,ChinaAnswer,1,send,rinfo);
        }
        if(typeof TrustAnswer == "undefined"){
            TrustAnswer = request;
            console.log("Timeout exceeded, giving up TrustDNS");
            JudgeResult(TrustAnswer,ChinaAnswer,2,send,rinfo);
        }
    }, config.Timeout)
    //接下来的逻辑在JudgeResult，它会负责发Response
};

function JudgeResult(TrustAnswer,ChinaAnswer,WhoAMI,send,rinfo){
    if(typeof ChinaAnswer != "undefined" && typeof TrustAnswer != "undefined" && (ChinaAnswer.sent == true || TrustAnswer.sent == true)){
        // 判断是否已经发出回包
        return;
    }
    switch(WhoAMI){
        case 1:
            // 触发Judge的是可信DNS返回
            if(TrustAnswer.answers.length == 0 && typeof ChinaAnswer != "undefined" && ChinaAnswer.answers.length == 0){
                // 两个DNS都没查询到结果
                send(TrustAnswer);
                utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
                break;
            }else if(TrustAnswer.answers.length == 0){
                // 暂时只是可信DNS没查到结果
                // 跳过 等中国DNS查询
                break;
            }
            var AnswerIP = [];
            for(q of TrustAnswer.answers){
                if(q.type == dns.Packet.TYPE.A){
                    AnswerIP.push(q.address);
                }
            }
            if(AnswerIP.length == 0){
                // 不含IP地址，可能是其他类型记录
                // 直接返回
                send(TrustAnswer);
                utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
                break;
            }
            if(CHNRoute.containsAny(AnswerIP)){
                // 返回的包含中国IP
                // 直接返回
                send(TrustAnswer);
                utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
                break;
            }
            if(CDNIPRange.containsAny(AnswerIP)){
                // 返回的包含CDN IP
                // 需要进行RST检测
                send(TrustAnswer);
                utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
                for(q of AnswerIP){
                    AddIPSet(q,TrustAnswer.questions[0].name,true);
                }
                break;
            }
            if(typeof ChinaAnswer != "undefined"){
                // 中国DNS已经做出了判断
                send(TrustAnswer);
                utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
                // 检测两个DNS的结果是否一致，不一致则为被污染
                let same = false;
                for(c of ChinaAnswer.answers){
                    if(c.type == dns.Packet.TYPE.A && AnswerIP.includes(c.address)){
                        same = true;
                    }
                }
                for(q of AnswerIP){
                    AddIPSet(q,TrustAnswer.questions[0].name,same);
                }
                break;
            }
            // 中国DNS还未回应
            // 等待中国DNS
            break;
        case 2:
            // 触发Judge的是中国DNS返回
            if(ChinaAnswer.answers.length == 0 && typeof TrustAnswer != "undefined" && TrustAnswer.answers.length == 0){
                // 两个DNS都没查询到结果
                send(ChinaAnswer);
                utils.GenerateLog(ChinaAnswer,rinfo,"(ChinaDNS)");
                break;
            }else if(ChinaAnswer.answers.length == 0){
                // 暂时只是中国DNS没查到结果
                // 跳过 等可信DNS查询
                break;
            }
            var AnswerIP = [];
            for(q of ChinaAnswer.answers){
                if(q.type == dns.Packet.TYPE.A){
                    AnswerIP.push(q.address);
                }
            }
            if(AnswerIP.length == 0){
                // 不含IP地址，可能是其他类型记录
                // 直接返回
                send(ChinaAnswer);
                utils.GenerateLog(ChinaAnswer,rinfo,"(ChinaDNS)");
                break;
            }
            if(CHNRoute.containsAny(AnswerIP)){
                // 返回的包含中国IP
                // 直接返回
                send(ChinaAnswer);
                utils.GenerateLog(ChinaAnswer,rinfo,"(ChinaDNS)");
                break;
            }
            if(CDNIPRange.containsAny(AnswerIP)){
                // 返回的包含CDN IP
                // 需要进行RST检测
                send(ChinaAnswer);
                utils.GenerateLog(ChinaAnswer,rinfo,"(ChinaDNS)");
                for(q of AnswerIP){
                    AddIPSet(q,ChinaAnswer.questions[0].name,true);
                }
                break;
            }
            // 不符合以上情况
            // 使用可信DNS结果，没有则等待
            if(typeof TrustAnswer != "undefined"){
                // 可信DNS已经做出了判断
                if(TrustAnswer.answers.length != 0){
                    send(TrustAnswer);
                    utils.GenerateLog(TrustAnswer,rinfo,"(TrustDNS)");
                    // 检测两个DNS的结果是否一致，不一致则为被污染
                    let same = false;
                    for(c of TrustAnswer.answers){
                        if(c.type == dns.Packet.TYPE.A && AnswerIP.includes(c.address)){
                            same = true;
                        }
                    }
                    for(q of AnswerIP){
                        // 被污染时 same = false 则直接添加
                        // 未被污染时 same = true 进行RST检测
                        AddIPSet(q,TrustAnswer.questions[0].name,same);
                    }
                }else{
                    // 可信DNS返回空，中国DNS有结果
                    send(ChinaAnswer);
                    utils.GenerateLog(TrustAnswer,rinfo,"(ChinaDNS)");
                }
                break;
            }
            break;
    }
}

/**
 * 进行可选的 HTTP(S) RST 检测并添加被干扰的记录到 IPSet
 * @param {string} ip 要添加/检测的 IP
 * @param {string} host RST 检测时请求的 Hostname
 * @param {boolean} check 是否进行 RST 检测
 */
async function AddIPSet(ip, host, check = false) {
    if (check && config.AutoDetectRST) {
        console.log(`Performing HTTP(S) RST Check for ${host} on ${ip}`);
        const timeStart = new Date();
        if (!await utils.RSTCheck(host, ip)) {
            console.log(`${host} on ${ip} RST Check passed (responsed in ${(new Date() - timeStart)}ms)`);
            return;
        }
    }
    const setname = config.IpsetToAdd;
    if (!setname) {
        return;
    }
    execFile('/usr/sbin/ipset', ['add', setname, ip], (err) => {
        if (err) {
            console.error(`An error occurred when adding ${ip} to the set ${setname}: ${err.message}`);
        } else {
            console.log(`${ip} was added to the set ${setname}`)
        }
    });
}

init();

// Dirty Patching...
// 暂时Patch，将来补完支持（也许永远不会有）
// 只是为了不出现error log
dns.Packet.TYPE.WTF = 0; //我也不知道这是什么
dns.Packet.TYPE.OPT = 41;
dns.Packet.Resource.OPT =
dns.Packet.Resource.PTR =
dns.Packet.Resource.WTF = {
    decode: function(){
      return this;
    },
    encode: function(){
        return this;
    }
}