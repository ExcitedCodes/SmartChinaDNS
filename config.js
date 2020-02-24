module.exports = {
    "Listen":"dns://0.0.0.0:53",
    "Exclusive":true, // 是否独占端口
    "ChinaDNS":{
        Type:"dns",
        Addr:"223.5.5.5:53"
    },
    "TrustDNS":{
        Type:"doh",
        Timeout:4000, // 这个属性只有DoH能用，普通DNS的Timeout是Node默认设定无法更改
        URL:"https://1.1.1.1/dns-query"
    },
    "CDNIPRange":"ipdb/cdnip.txt", // 自整理 版本2020-02-22
    "CHNRoute":"ipdb/chnroute.txt", // IPIP.net 版本2020-01-16 github.com/17mon/china_ip_list
    "BlackList":"ipdb/gfwlist.txt", // fancyss 版本2019-02-05
    "WhiteList":"ipdb/chinalist.txt", // fancyss 版本2019-02-05
    "IpsetToAdd":"gfwlist",
    "AutoDetectRST":true // 对未知域名自动进行HTTP(S) RST检测，关闭就全部加IPSET
}