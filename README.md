# CdnHunter

参考 [Eeyes](https://github.com/EdgeSecurityTeam/Eeyes) 的设计思路，用 Go 重新实现的资产测绘前置工具：**从一批域名中筛出真实 IP，并按 /24 聚合成 C 段**。

唯一直接依赖是 `github.com/miekg/dns`（自己构造 DNS 查询以拿到完整 CNAME 链与 TTL），其余全部是标准库。

> Eeyes 原仓库的代码已被作者移除，本项目未复用其任何代码，是按「域名 → 剔除 CDN → 真实 IP → C 段」这条思路独立实现，并把判定依据全部写在源码里以便审计与二次开发。

## 为什么做这个

Eeyes 的形态是「输入一批域名 → 判断哪些走 CDN → 把真实 IP 归并成 C 段」，用于资产测绘阶段快速定位目标真实资产。本项目把这条链路用 Go 重写，逻辑透明、可二次开发。

## 判定逻辑

对每个域名依次过四个维度，任一命中即判为 CDN 并短路：

| 顺序 | 维度 | 方法 | 说明 |
|---|---|---|---|
| 1 | **完整 CNAME 链逐跳匹配** | 逐跳跟随 CNAME，链上每一跳都过内置 35 家厂商特征库 | 最廉价、最准。逐跳而非只看链尾，因为 CDN 特征常常出现在中间跳 |
| 2 | **IP 段归属** | 解析出的 IP 是否落在内置 CDN 网段库（53 条） | 治 anycast 与 CNAME 不暴露的假阴性 |
| 3 | **HTTP 响应头** | 读 `Cf-Ray`、`X-Akamai-*`、`X-Served-By`、`Ali-Swift-*`、`Server: bws/bfe`、`Via: ens-cache`、`X-Cache` | 治边缘节点落在运营商机房的站（淘宝、百度、新浪） |
| 4 | **多 DNS 解析比对** | 三台公共 DNS（223.5.5.5 / 119.29.29.29 / 114.114.114.114）IP 集合不一致 | 兜底；假阳性最高，所以放最后，并带同域豁免 |

**维度四的同域豁免**：多 DNS 不一致时，若 CNAME 链尾仍落在目标自身的注册域内（如 `www.example.edu → www.lb.example.edu`），判定为...

维度顺序是按「代价 / 确定性」排的：越便宜越确定的在前，代价高且有误判风险的 HTTP 探测与多 DNS 比对在后，并用短路避免无谓请求。

## CNAME 链与 TTL（相对 net.Resolver 的核心增量）

标准库 `LookupCNAME` 只返回**最终一跳**规范名，中间跳全部丢失，也拿不到 TTL。Eeyes 这类工具的价值恰恰在于能看到「`www.taobao.com` 其实 CNAME 到 `www.taobao.com.danuoyi.tbcache.com`」这种链路细节。

`dnsquery.go` 的做法：

- 用 `miekg/dns` 构造 `TypeA` 查询，`RecursionDesired=true`，`SetEdns0(1232)` 避免超过 512 字节被截断
- 先 UDP，失败或 `Truncated=true` 时自动退 TCP 重试一次
- 逐跳跟随：只把**当前节点发出**的 CNAME 作为下一轮查询目标，避免整链重复跟随；最多 10 跳，带环路检测
- 递归响应里已经带了 A 记录时直接结束（说明服务器已把整链展开）
- 收集整条链上每条记录的 TTL，取最小值作为该域名的 `ttl_min`

TTL 的实战意义：主流站点 TTL 普遍在 5–40 秒，极短 TTL 说明调度频繁（典型是 GSLB 轮询或跨运营商调度）。第三组里那所高校的 TTL 只有 **1 秒**，这就是自建 DNS 轮询的直接证据。

输出里链单独占一行：

```
www.jd.com            CDN    京东自建CDN       10     CNAME 链（3 跳）命中 京东自建CDN (.qianxun.com)
                          └ www.jd.com.gslb.qianxun.com → www.jd.com.s.galileo.jcloud-cdn.com → wwwv6.jcloudimg.com
```

## 四个关键头：Server / CF-Ray / X-Cache / Via

这四个头是识别 CDN 最直接的证据面。加 `-headers` 会把实际抓到的原始值打出来：

```
example.com       CDN   Cloudflare   109   IP 104.20.23.154 落在 Cloudflare 网段
                      H> Server=cloudflare | CF-Ray=a5f84b281fc4534f-LAX | X-Cache=- | Via=-
www.taobao.com    CDN   阿里自建缓存  30    CNAME 链命中 阿里自建缓存 (.tbcache.com)
                      H> Server=Tengine | CF-Ray=- | X-Cache=HIT TCP_MEM_HIT dirn:-2:-2 | Via=cache35.l2et135-6[383,334,200-0,C]
```

实测出来的头指纹：

| 厂商 | 头证据 |
|---|---|
| Cloudflare | `Server: cloudflare` + `CF-Ray: xxxx-LAX`（后缀是边缘节点的 IATA 机场码，LAX=洛杉矶） |
| 阿里云 / 淘宝 | `Server: Tengine` + `X-Cache: HIT TCP_MEM_HIT` + `Via: cache35.l2et135-6...`（l2et = 二层边缘节点） |
| 百度 | `Server: BWS/1.1` |
| 京东 | `Via: http/1.1 ORI-CLOUD-HB1-MIX-62 (jcs [...])` |
| 新浪 | `Via: http/1.1 ctc.guangzhou.union.299 (ApacheTrafficServer/...)` |
| 网宿 | `Server: wswaf` + `Via: ... uproxy-4` |
| 蓝汛 | `X-Cache: HIT from cache.51cdn.com` |
| 腾讯 | `Server: tRPC-Gateway`（业务网关，非 CDN 证据，不作为判据） |

**判定顺序（关键）**：厂商专属头 → Server 强规则 → Via → 缓存层弱信号（X-Cache 系列）。

弱信号必须最后判。规则写反的后果很具体：淘宝同时有 `X-Cache: HIT` 和 `Via: ...l2et135`，如果 X-Cache 抢先命中，厂商就被降级成含糊的「缓存层」，丢掉 Via 里更精确的归属。这条顺序有单元测试锁着（`httpcheck_test.go`）。

`CF-Ray` 的后缀还能直接读出边缘节点城市：`-LAX` 洛杉矶、`-SJC` 圣何塞、`-HKG` 香港、`-NRT` 东京。做资产测绘时这能判断请求被调度到了哪个节点。

## 用法

```
cdnhunter.exe -d example.com                     单个域名
cdnhunter.exe -f domains.txt                     域名文件，一行一个
cdnhunter.exe -f domains.txt -o result.csv       同时输出 CSV
cdnhunter.exe -f domains.txt -t 16               提高并发
cdnhunter.exe -f domains.txt -top 20             只看前 20 个 C 段
cdnhunter.exe -d example.com -ns 8.8.8.8,1.1.1.1 自定义 DNS
cdnhunter.exe -f domains.txt -nohttp             跳过 HTTP 探测（快，但漏判自建 CDN）
cdnhunter.exe -f domains.txt -headers           打印实际抓到的 Server/CF-Ray/X-Cache/Via
cdnhunter.exe -f domains.txt -ipdb my-ipdb.txt   用外部 IP 段库覆盖内置库
```

| 参数 | 默认 | 说明 |
|---|---|---|
| `-d` | 空 | 单个域名 |
| `-f` | 空 | 域名文件路径 |
| `-o` | 空 | CSV 输出路径（自动加 BOM，Excel 直接打开不乱码） |
| `-t` | 8 | 并发数 |
| `-timeout` | 3 | 单次 DNS 查询超时（秒），同时作为 UDP 与 TCP 的 Client.Timeout |
| `-ns` | 三公共 DNS | 自定义 DNS 服务器，逗号分隔 |
| `-top` | 0 | C 段汇总只显示前 N 个，0 表示全部 |
| `-ipdb` | 内置 | 外部 IP 段库，格式 `<CIDR> <厂商名>`，`#` 注释 |
| `-nohttp` | false | 关闭 HTTP 响应头探测 |
| `-httptimeout` | 8 | HTTP 探测超时（秒） |
| `-headers` | false | 打印实际抓到的 Server/CF-Ray/X-Cache/Via 原始值；会强制对每个域名发一次 HTTP 请求 |
| `-plain` | 空 | 只输出结果便于管道串联：`host`=仅真实域名，`ip`=仅真实 IP |

CSV 字段：`domain, is_cdn, vendor, reason, cname, cname_chain, ttl_min, server, cf_ray, x_cache, via, ips, c_segments`
（`cname` 是链尾，`cname_chain` 是空格分隔的完整链；四个头字段在未开 `-headers` 时为空）

## 管道串联

`cdnhunter` 支持从 stdin 读域名，可以直接接在 `subfinder` 后面：

```bash
# 子域枚举 → 剔除 CDN → 只出真实 IP
subfinder -d example.com -silent | cdnhunter -plain ip

# 子域枚举 → 只出真实域名 → 继续喂 httpx
subfinder -d example.com -silent | cdnhunter -plain host | httpx -silent -status-code

# IP 清单落盘，再交给 fscan
subfinder -d example.com -silent | cdnhunter -plain ip > real-ips.txt
fscan -hf real-ips.txt -nobr -nopoc
```

PowerShell 里同样可用（`|` 对 native 命令直通）：

```powershell
subfinder.exe -d example.com -silent | .\cdnhunter.exe -plain ip
```

`-plain` 模式下所有进度提示走 **stderr**，stdout 只留结果行，不会污染下游。

**stdin 的三个坑（都已处理，且都是实测踩出来的）**：

1. **管道永不关闭会卡死**。被 IDE / CI / 自动化工具以管道方式启动时，stdin 是「已连接但不关闭」的管道，直接 `Scanner` 会一直等 EOF。
2. **上游冷启动比想象慢**。实测 `subfinder -d xxx -silent` 从启动到吐出第一行要 **22–24 秒**（初始化配置 + 多个被动源并发查询）。最早设的 800ms 首行超时，会让整条管道直接判「没有输入目标」。
3. **done 与缓冲数据竞争**。读取 goroutine 和消费端各用一套 `done` channel 时，`close(done)` 会与 `lines` 缓冲区里剩余的行一起就绪，select 随机选中 done 就只读到首行。正确做法是只用一个 channel，读完 `close` 它，靠 Go 的 channel 语义把缓冲读空。

最终等待策略：

| 场景 | 首行等待 | 行间空闲 |
|---|---|---|
| 命令行给了 `-d` / `-f`（stdin 只是可选补充） | 1.2s | 45s |
| 没有任何显式目标（显然要靠管道） | 90s | 45s |

无显式目标时会在 stderr 打一行「等待 stdin 输入（最长 90s…）」，不会让人误以为卡死。校验结果：`subfinder | cdnhunter -plain ip` 完整读到 30 行、耗时 28.8 秒、退出码 0。

## 实测记录

三组样本，分别验证「能不能认 CDN」「会不会误判自建 CDN」「会不会误判政企自建」。**仅做 DNS 查询与一次 HTTP GET，未对任何站点发起额外请求。**

**第一组：主流站点（应全判 CDN）**

| 域名 | 判定 | 依据 | TTL |
|---|---|---|---|
| example.com | CDN / Cloudflare | IP 落在内置 CF 段 | 35 |
| www.cloudflare.com | CDN / Cloudflare | IP 落在内置 CF 段 | 116 |
| www.baidu.com | CDN / 百度自建接入 | CNAME `www.a.shifen.com` | 33 |
| www.taobao.com | CDN / 阿里自建缓存 | CNAME `...danuoyi.tbcache.com` | 35 |
| www.qq.com | CDN / 腾讯云 CDN | CNAME `ins-...ias.tencent-cloud.net` | 35 |
| github.com | CDN / — | 多 DNS 不一致 | 10 |

6/6 判 CDN。

**第二组：国内自建 CDN（考验特征库覆盖）**

| 域名 | 判定 | 依据 |
|---|---|---|
| www.163.com | CDN / 阿里云CDN | 头 `Ali-Swift-Global-Savetime`；链 `163jiasu.com → kunluncan.com` |
| www.jd.com | CDN / 京东自建CDN | 链 `gslb.qianxun.com → jcloud-cdn.com → jcloudimg.com`（3 跳） |
| www.zhihu.com | CDN / 腾讯云 EdgeOne | 链 `c.vedcdnlb.com` |
| 某政府门户 | CDN / 白山云 | 链 `bsgslb.cn`（2 跳） |
| www.sina.com.cn | CDN / 缓存层 | 头 `X-Cache=HIT.171`；链 `spool.grid.sinaedge.com` |
| www.ctrip.com | CDN / 携程自建CDN | 链 `ctripgslb.net → wsglb0.com`（3 跳） |

6/6 判 CDN。这组里京东、携程、知乎的厂商识别，全部是靠**完整链**才做出来的——只看链尾也能看到，逐跳匹配让依据更明确。

**第三组：政企/高校类站点（应出现 REAL）**

> 这一组的原始目标清单属本地测试数据，不入库（见 `.gitignore`）。下表只保留判定结论、厂商与 TTL，域名与 IP 已脱敏。

| 站点类型 | 判定 | 依据 | TTL |
|---|---|---|---|
| 票务类 | CDN / 蓝汛 | CNAME 命中 `.lxdns.com` | 13 |
| 媒体门户 | CDN / 网宿科技 | CNAME 命中 `.wswebpic.com` | 21 |
| 政务门户 | CDN / 奇安信云WAF | CNAME 命中 `.qaxcloudwaf.com` | 35 |
| 科研机构 | REAL | 自建 IP（略） | 2614 |
| 高校 A | REAL | 自建 IP（略） | 1461 |
| 高校 B | REAL | 自建 IP（略） | 1 |

3 CDN / 3 REAL。三组 TTL 分布很能说明问题：CDN 站 13–35 秒，政企自建 1461–2614 秒，高校 B 只有 1 秒（GSLB 轮询）。**TTL 量级本身就是一条独立线索。**

高校 B 那条是这轮最有价值的样本：加同域豁免之前它被判成 CDN（多 DNS 不一致），加之后修正回 REAL——它的 CNAME 链尾是 `www.lb.<自身域名>`，属于校内负载均衡，不是第三方 CDN。

## 当前局限（诚实说明）

1. **自建 CDN 的语义歧义**。百度、淘宝、京东用的是**自有基础设施**，IP 归属厂商自己。判成 CDN 意味着这些 IP 不进 C 段聚合——从「剔除公共共享接入层」看是对的，从「挖厂商自有资产」看就是漏的。业务上这两个目标要分开。
2. **同域豁免会漏掉「客户自有域名 CNAME 到 CDN」的形态**。如果 CDN 厂商分配的是客户域下的子域（`cdn.customer.com`），豁免规则会把它当自建放行。这种情况在国内较少（多数厂商用自有域名）。
3. **anycast + 干净响应头 + IP 不在库**仍会漏判，只能靠多 DNS 兜底，而多 DNS 有假阳性。
4. **HTTP 探测受反爬影响**。部分站点对非浏览器指纹返回 403 或不同头，该维度静默失效（表现为不命中，不改判定）。`-nohttp` 可显式关掉。政企站的 `Server` 头常为空，就是这类情况。
5. **X-Cache 有假阳性**。自建 nginx `proxy_cache`、Varnish、Squid 都会发这个头，所以它被标成弱信号（vendor 写「缓存层(疑似CDN)」，reason 带实际值），只在厂商专属头和 Via 都没命中时才用。看到「缓存层」不等于第三方 CDN，需要人工再确认。
6. **TTL 未参与判定**。目前只做展示与人工参考，没有做成第五维度——因为 TTL 短也可能只是权威 DNS 的正常配置，单独作为判据假阳性太高。
7. **IP 段库会过时**。内置换库是某一时点的快照，生产环境应定期从各厂商官方接口拉取后用 `-ipdb` 覆盖。
8. **`sameRegistrableDomain` 用「最后两段」近似注册域**。对 `xxx.edu.cn`、`xxx.co.uk` 这类多级公共后缀会取到 `edu.cn`，判断偏宽松。真要做准需要引入 Public Suffix List。

## 迭代方向

- [x] 引入 CDN 厂商 IP 段库，做第三维度判定
- [x] 改用 `github.com/miekg/dns` 拿完整 CNAME 链与 TTL
- [x] 加 HTTP 探测：读取 `Server`、`Via`、`X-Cache`、`CF-Ray` 等响应头辅助判定
- [x] 支持从 stdin 读域名，便于与 `httpx`、`subfinder` 管道串联（`-plain host|ip`）
- [ ] 接入 FOFA / Quake API，通过 `cert` 语法反查同证书域名
- [ ] 输出 Markdown 报告，直接嵌进测绘流水线
- [ ] 把 IP 段库的更新做成独立脚本（拉官方接口 → 合并去重 → 生成 ipdb.txt）
- [x] 加单元测试：`httpcheck_test.go` 用真实抓包头做样本，锁住判定顺序（`go test ./...`）
- [ ] 引入 Public Suffix List 修正同域豁免的边界

## 编译

```bash
# 直接装到 $GOBIN（需要 Go 1.25+）
go install github.com/whb135/CdnHunter@latest

# 或在仓库内本地构建
go build -o cdnhunter.exe .
# Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o cdnhunter_linux_amd64 .
```

依赖只有 `github.com/miekg/dns v1.1.73`（间接依赖 `golang.org/x/net`、`golang.org/x/sys`）。国内拉取需要配代理：

```bash
go env -w GOPROXY=https://goproxy.cn,https://goproxy.io,direct
```

## 合规声明

本工具仅做 DNS 解析、一次 HTTP GET 与结果归纳，不发起端口扫描或漏洞探测。**只对你拥有、或已获得书面授权的域名使用**。
