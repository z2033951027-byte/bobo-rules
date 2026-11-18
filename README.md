# bobo-rules
rules mod for vpn

## 分流规则 2.3.3（2026-11-18）

基线是 main 的 01a24d8。正式入口为 sing-box 单个 PROXY 规则集，未命中时由宿主走 DIRECT。订阅、节点、策略组和手动切换均由客户端管理。手机原有的[远程文本规则链接](https://raw.githubusercontent.com/z2033951027-byte/bobo-rules/main/compat-tests/bobo-proxy-candidate-v1.list)已同步到 2.3.3。测试直接解析整份文本，核对逻辑表达式与 JSON 规则一致，81 项域名和 IP 匹配全部通过。相对旧文本有 17 项改判。手机导入、刷新缓存和实际出站仍待真机验证。同目录的 logic-probe 仅用于格式探测。

| 调整 | 原因及范围 |
| --- | --- |
| 为 edge-byted.com、haimian.com、alivecdn.com、wesure100.com、ydshengxue.com 及其子域补直连 | 基线实测均命中代理。五域分别来自字节、阿里、腾讯、网易的社区规则，固定版本 SagerNet 国内集也逐一命中。沿用原国内域名与 IP 数据，只补已复核项。 |
| 为 fonts.googleapis.com、fonts.gstatic.com、fontfiles.googleapis.com、connectivitycheck.gstatic.com、dl.google.com、dl.l.google.com 补精确直连例外 | 六个主机均在原国内域名库。原来的代理优先项覆盖了它们。仅放行字体、软件下载和联网检测六个主机，Google 登录、地图和未列名子域沿用原策略。 |
| 精确补入 home.arpa | 原规则覆盖子域，却把区域名称本身交给代理。补齐家庭网络保留域名边界。 |

Windows amd64 官方 sing-box 1.14.2 对候选 JSON 完成编译、SRS v1 文件头检查和反编译。原版与候选二进制逐条比较 81 个离线输入，候选通过 81 项，17 项按预期从代理变为未命中。仓库工作流的 verification.json 记录每个目标、期望与实际匹配。测试中的 cdn 子域用于验证标签边界，不代表实际线上端点。

基线 JSON、SRS 和构建脚本可从 01a24d8 取回。使用同一版本的 sing-box 可执行以下只读复核（输出文件请放在临时目录）。rule-set match 的结果以输出中是否出现 match rules.[0] 判定，未命中也可能正常退出。

```text
sing-box rule-set compile --output <临时目录>/candidate.srs bobo-final-proxy.json
sing-box rule-set match --format binary bobo-final-proxy.srs fonts.gstatic.com
sing-box rule-set match --format binary bobo-final-proxy.srs accounts.google.com
```

未验证客户端导入、实际 DNS/FakeIP、域名和解析 IP 同时出现时的最终出站、手机或 Windows 软件连通性、节点切换耗时。单独的 IP 连接仍按原 IP 规则匹配。线上产物由仓库原有的 Build Bobo Rules 工作流编译和验证。

依据见 [sing-box 规则格式](https://sing-box.sagernet.org/configuration/rule-set/headless-rule/)、[复核的 SagerNet 国内规则](https://github.com/SagerNet/sing-geosite/blob/f845ad54a708500aa9c76be84cfaa04cc7141edd/geosite-cn.srs)、[应用域名来源](https://github.com/v2fly/domain-list-community/tree/bc3a8f5e24792303cf82bfff33b1ff164a0e4b3c/data)、[RFC 8375](https://www.rfc-editor.org/rfc/rfc8375)。
