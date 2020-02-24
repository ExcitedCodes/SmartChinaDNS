const https = require("https");
const http = require("http");
const agent = new https.Agent({keepAlive: true});
const dns = require("dns2");
const base64url = require("base64url");
const fs = require('fs');
const readline = require('readline');
const net = require('net');

function emptyPacket(packet){
    let ep = new dns.Packet(packet);
    ep.header.qr = 1;
    return ep;
}

const LoadIP = (filepath) => new Promise((resolve,reject) => {
    try{
        let fsobj = fs.createReadStream(filepath).on('error',(e) => {
            console.log(`An error occured when reading ${filepath}: ${e.message}`);
            resolve([]);
        })
        let rl = readline.createInterface({input: fsobj});
        let IPList = [];
        let LineCounter = 0;
        rl.on('line',(line) => {
            LineCounter++;
            if(line.indexOf('#') !== 0){
                if(/^([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?$/.test(line)){
                    IPList.push(line);
                }else{
                    console.log(`File ${filepath}:${LineCounter} does not contains a valid IPv4 address with proper optional CIDR notation`)
                }
            }
        });
        rl.on('close',() => {
            resolve(IPList);
        })
    }catch(e){
        console.log(`An error occured when reading ${filepath}: ${e.message}`);
        resolve([]);
    }
});




const DoHRequest = (hostname,port,path,timeout,packet) => new Promise((resolve,reject) => {
    let options = {
        hostname: hostname,
        port: port,
        path: path + "?dns=" + base64url(packet.toBuffer()),
        method: "GET",
        headers:{
            "accept": "application/dns-message",
            "User-Agent": "SmartChinaDNS",
            "Connection": "Keep-Alive"
        },
        agent: agent,
        timeout:timeout
    }
    let req = https.request(options);
    req.on('timeout', () => {
        reject(`Timed out requesting https://${hostname}:${port}${options.path}`);
        req.abort();
    });
    req.on('response',res => {
        res.on('data', data => {
            
            switch(res.statusCode){
                case 200:
                    let answerPacket = new dns.Packet(packet);
                    answerPacket.header.qr = 1;
                    answerPacket.additionals = [];
                    answerPacket.header.arcount = 0;
                    answerPacket.answers=dns.Packet.parse(data).answers;
                    resolve(packet);
                    break;
                default:
                    reject('Server returns error ' + res.statusCode);
            }
        });
    });
    req.on('error',err => {
        reject(err.message);
    })
    req.end();
});

const DNSRequest = (dnsobject,packet) => new Promise((resolve,reject) => {
    for(q of packet.questions){
        dnsobject.resolve(q.name,getKeyByValue(dns.Packet.TYPE,q.type),(err,records) => {
            if(err){ 
                if(err.code == "ENODATA"){
                    resolve(emptyPacket(packet));
                    return;
                }
                reject(`DNS Error ${err.code}`)
                return;
            }
            let response = new dns.Packet(packet);
            response.header.qr = 1;
            if(records.length == 0){
                resolve(emptyPacket(packet));
                return;
            }
            switch(q.type){
                case 0x01:
                    records.forEach(r => {
                        response.answers.push({
                            name: q.name,
                            class: 1,
                            address: r,
                            type: dns.Packet.TYPE.A
                        })
                    });
                    break;
                case 0x1C:
                    records.forEach(r => {
                        response.answers.push({
                            name: q.name,
                            class: 1,
                            address: r,
                            type: dns.Packet.TYPE.AAAA
                        })
                    });
                    break;
                case 0x02:
                    records.forEach(r => {
                        response.answers.push({
                            name: q.name,
                            class: 1,
                            ns: r,
                            type: dns.Packet.TYPE.NS
                        })
                    });
                    break;
                case 0x05:
                    records.forEach(r => {
                        response.answers.push({
                            name: q.name,
                            class: 1,
                            domain: r,
                            type: dns.Packet.TYPE.CNAME
                        })
                    });
                    break;
                case 0x06:
                    response.answers.push({
                        name: q.name,
                        class: 1,
                        domain: r.nsname,
                        type: dns.Packet.TYPE.SOA
                    })
                    break;
                case 0x10:
                    records[0].forEach(r => {
                        response.answers.push({
                            name: q.name,
                            class: 1,
                            data: r,
                            type: dns.Packet.TYPE.TXT
                        })
                    });
                    break;
                case 0x0F:
                    records.forEach(r => {
                        response.answers.push({
                            name: q.name,
                            exchange: r.exchange,
                            class: 1,
                            priority: r.priority,
                            type: dns.Packet.TYPE.MX
                        })
                    });
                    break;
                default:
                    reject('Not Implemented')
                    return;
            }
            resolve(response);
        });
    }
});


const RSTCheck = (host,ip) => new Promise((resolve,reject) => {
    let req1 = https.request({
        hostname: ip,
        port: 443,
        method: "GET",
        headers:{
            "User-Agent": "SmartChinaDNS",
            "Host": host
        },
        setHost: false,
        timeout:10000
    });
    let req2 = http.request({
        hostname: ip,
        port: 80,
        method: "GET",
        headers:{
            "User-Agent": "SmartChinaDNS",
            "Host": host
        },
        setHost: false,
        timeout:10000
    });
    req1.on('error',(err)=>{
        resolve(err.code == "ECONNRESET");
    })
    req2.on('error',(err)=>{
        resolve(err.code == "ECONNRESET");
    })
    req1.on('response',()=>{
        resolve(false);
    })
    req2.on('response',()=>{
        resolve(false);
    })
    req1.end();
    req2.end();
});


function getKeyByValue(object, value){
    return Object.keys(object).find(key => object[key] === value);
}

class DomainMatcher {
    constructor(){
        this.DomainList = [];
    }
    LoadFromFile = (filepath) => new Promise((resolve,reject) => {
        try{
            let fsobj = fs.createReadStream(filepath).on('error',(e) => {
                console.error(`An error occured when reading ${filepath}: ${e.message}`);
                resolve([]);
            })
            let rl = readline.createInterface({input: fsobj});
            let LineCounter = 0;
            rl.on('line',(line) => {
                if(line.indexOf('#') !== 0){
                    this.DomainList.push(line);
                }
            });
            rl.on('close',() => {
                resolve();
            })
        }catch(e){
            console.error(`An error occured when reading ${filepath}: ${e.message}`);
            resolve();
        }
    });
    contains(Domain){
        Domain = Domain.toLowerCase();
        for(let m of this.DomainList){
            var i = Domain.lastIndexOf(m)
            if(i == 0 || Domain[i - 1] == ".") return true;
        }
        return false;
    }
}

function GenerateLog(FinalAnswer,rinfo,comment = ""){
    FinalAnswer.sent = true;
    for(q of FinalAnswer.answers){
        let ansData;
        switch(q.type){
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
        console.log(`Answered[${getKeyByValue(dns.Packet.TYPE,q.type)}] ${q.name} to ${rinfo.address}: ${ansData} ${comment} +${new Date().getTime() - rinfo.timeStart}ms`);
    }
    if(FinalAnswer.answers.length == 0){
        console.log(`Answered[${getKeyByValue(dns.Packet.TYPE,q.type)}] ${q.name} to ${rinfo.address}: NODATA ${comment} +${new Date().getTime() - rinfo.timeStart}ms`);
    }
}



module.exports = { DoHRequest, getKeyByValue, DNSRequest, LoadIP, DomainMatcher, GenerateLog, emptyPacket, RSTCheck };