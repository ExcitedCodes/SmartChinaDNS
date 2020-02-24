# Smart China DNS

这是一个更好的 ChinaDNS，旨在用最智能的方式返回正确的结果。

由于 GFWList 更新并不总是及时全面，单纯用 GFWList 模式的话有时候经常会遇到某个域名莫名其妙被污染了，又得去添加；

又不希望用 ChnRoute 模式导致所有外国网站都走代理。

所以做了一个 SmartChinaDNS，可以智能快速判断网站是否被墙，并且做出对应行为（IPSET）、返回正确结果。

SmartChinaDNS 将 GFWList 和 ChnRoute 的优点融合起来，为你提供正确的解析结果和被墙判断。

### 注意

这是一个不完善的 DNS 服务器实现，并非 100% 符合 RFC 1035、RFC 1034 和 RFC 8484。

它不支持 EDNS，而且只支持 A、AAAA、CNAME、NS、MX、TXT 和 SOA 记录。

但是我相信这已经足够完成该服务器的设计目标用途，所以除非有特别关键的问题，否则不会添加额外的支持。