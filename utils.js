const fs = require('fs');
const dns = require("dns2");
const http = require("http");
const https = require("https");
const agent = new https.Agent({ keepAlive: true });
const readline = require('readline');
const base64url = require("base64url");

/**
 * 记录类型到 DNS 返回包字段的映射, 用于 DNSRequest
 */
const TYPE_FIELD_MAP = {
    0x01: 'address', // A
    0x02: 'ns', // NS
    0x05: 'domain', // CNAME
    0x06: 'domain', // SOA
    0x10: 'data', // TXT
    0x0F: (r, row) => {
        row.exchange = r.exchange;
        row.priority = r.priority;
    }, // MX
    0x1C: 'address', // AAAA
};

/**
 * 将 DNS Packet 标记为返回数据包, 以便告知客户端 NO DATA
 * @param {*} packet 需要标记的数据包
 */
function emptyPacket(packet) {
    packet.header.qr = 1;
    return packet;
}

/**
 * 读取一个纯文本文件并按行处理首字符不为 # 的行
 * @param {string} file 文件路径
 * @param {(line: string, lineNumber: int) => void} line 每行执行的回调
 * @param {() => void} finish 读取完成的回调
 * @param {(e) => void} error 出现错误的回调
 */
function readFile(file, line, finish, error) {
    try {
        let lineNumber = 0;
        readline.createInterface({
            input: fs.createReadStream(file)
                .on('error', error)
        }).on('line', l => {
            lineNumber++;
            if (l.length > 0 && l[0] != '#') {
                line(l, lineNumber);
            }
        }).on('close', finish);
    } catch (e) {
        error(e);
    }
}

/**
 * 读取 IP CIDR 文件, 验证并创建结果数组. 该函数不会调用 reject, 失败时 resolve 空数组
 * @param {string} file 文件路径
 */
const LoadIP = (file) => new Promise((resolve, _reject) => {
    const result = [];
    readFile(file, (line, counter) => {
        if (/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/.test(line)) {
            result.push(line);
        } else {
            console.log(`File ${file}:${counter} does not contains a valid IPv4 address with proper optional CIDR notation`);
        }
    }, () => resolve(result), (e) => {
        resolve([]);
        console.log(`Error occured while reading ${file}: ${e.message}`);
    });
});

/**
 * 进行 DOH 查询
 * @param {string} url 服务器URL, 此函数将直接在 URL 后添加 dns=Base64
 * @param {int} timeout HTTP 请求超时
 * @param {*} packet 查询包
 */
const DoHRequest = (url, timeout, packet) => new Promise((resolve, reject) => {
    const req = https.request(url + 'dns=' + base64url(packet.toBuffer()), {
        agent: agent,
        method: "GET",
        timeout: timeout,
        headers: {
            "Accept": "application/dns-message",
            "User-Agent": "SmartChinaDNS ",
            "Connection": "Keep-Alive"
        }
    }).on('timeout', () => {
        req.abort();
        reject(`HTTP time out requesting ${url}`);
    }).on('response', res => {
        res.on('data', data => {
            switch (res.statusCode) {
                case 200:
                    let answerPacket = new dns.Packet(packet);
                    answerPacket.header.qr = 1;
                    answerPacket.additionals = [];
                    answerPacket.header.arcount = 0;
                    answerPacket.answers = dns.Packet.parse(data).answers;
                    resolve(packet);
                    break;
                default:
                    reject('Server returns error ' + res.statusCode);
                    break;
            }
        });
    }).on('error', err => {
        reject(err.message);
    });
    req.end();
});

/**
 * 进行 DNS 查询
 * @param {*} dnsobject dns 对象
 * @param {*} packet 查询包
 */
const DNSRequest = (dnsobject, packet) => new Promise((resolve, reject) => {
    for (const q of packet.questions) {
        const type = getKeyByValue(dns.Packet.TYPE, q.type);
        dnsobject.resolve(q.name, type, (err, records) => {
            const response = emptyPacket(packet);
            if (err) {
                if (err.code == "ENODATA") {
                    resolve(response);
                } else {
                    reject(`DNS Error ${err.code}`)
                }
                return;
            }
            const key = TYPE_FIELD_MAP[q.type];
            if (!key) {
                reject(`Unimplemented Type: ${type}`);
                return;
            }
            for (const r of records) {
                let row = {
                    name: q.name,
                    type: q.type,
                    class: 1
                };
                if (typeof (key) === 'string') {
                    row[key] = r;
                } else {
                    key(r, row);
                }
                response.answers.push(row);
            }
            resolve(response);
        });
    }
});

/**
 * 执行 HTTP(s) RST 检测, 收到 RST 则返回 true
 * @param {string} host 检测时使用的 Hostname
 * @param {string} ip 要检测的 IP 地址
 */
const RSTCheck = (host, ip) => new Promise((resolve, _reject) => {
    const doCheck = (protocol, port) => {
        protocol.request({
            port: port,
            method: "HEAD", // We don't care the response, it's fine when server returns http error.
            hostname: ip,
            headers: {
                "Host": host,
                "User-Agent": "SmartChinaDNS"
            },
            setHost: false,
            timeout: 10000
        }).on('error', (err) => {
            resolve(err.code == "ECONNRESET");
        }).on('response', () => {
            resolve(false);
        }).end();
    };
    doCheck(http, 80);
    doCheck(https, 443);
});

/**
 * 通过 value 在 object 中搜索键
 * @param {*} object 要搜索的对象
 * @param {*} value 要搜索的值
 */
const getKeyByValue = (object, value) => Object.keys(object).find(key => object[key] === value);

class DomainMatcher {
    constructor() {
        this.DomainList = {};
    }

    LoadFromFile = (file) => new Promise((resolve, _reject) => readFile(file, (line, _counter) => {
        line = line.toLowerCase().split('.');
        let root = this.DomainList;
        for (let i = line.length - 1; i >= 0; i--) {
            if (root[line[i]] === undefined) {
                root[line[i]] = i == 0 ? true : {};
            }
            root = root[line[i]];
            if (root === true && i != 0) {
                // Already contained in a wider rule
                return;
            }
        }
    }, resolve, (e) => {
        resolve();
        console.log(`Error occured while reading ${file}: ${e.message}`);
    }));

    contains(domain) {
        let root = this.DomainList;
        domain = domain.toLowerCase().split('.');
        for (let i = domain.length - 1; root && i >= 0; i--) {
            root = root[domain[i]];
            if (root === true) {
                return true;
            }
        }
        return false;
    }
}

/**
 * @todo 独立Logger
 * 
 * @param {*} FinalAnswer 
 * @param {*} rinfo 
 * @param {*} comment 
 */
function GenerateLog(FinalAnswer, rinfo, comment = "") {
    FinalAnswer.sent = true;
    for (q of FinalAnswer.answers) {
        let ansData;
        switch (q.type) {
            case 0x01:
            case 0x1C:
                ansData = q.address;
                break;
            case 0x02:
                ansData = q.ns;
                break;
            case 0x05:
                ansData = q.domain;
                break;
            case 0x06:
                ansData = `primary ${q.primary} admin ${q.admin}`;
                break;
            case 0x0F:
                ansData = q.exchange;
                break;
            case 0x10:
                ansData = q.data;
                break;
            default:
                ansData = "error";
        }
        console.log(`Answered[${getKeyByValue(dns.Packet.TYPE, q.type)}] ${q.name} to ${rinfo.address}: ${ansData} ${comment} +${new Date().getTime() - rinfo.timeStart}ms`);
    }
    if (FinalAnswer.answers.length == 0) {
        console.log(`Answered[${getKeyByValue(dns.Packet.TYPE, q.type)}] ${q.name} to ${rinfo.address}: NODATA ${comment} +${new Date().getTime() - rinfo.timeStart}ms`);
    }
}

module.exports = { DoHRequest, getKeyByValue, DNSRequest, LoadIP, DomainMatcher, GenerateLog, emptyPacket, RSTCheck };
