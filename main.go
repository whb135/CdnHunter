package main

//   CdnHunter —— 复刻 Eeyes 的核心能力
//   输入域名清单（参数 / 文件 / stdin 管道），输出：CDN 判定 + 真实 IP + C 段聚合
//
//   判定逻辑（四维度，任一命中即判 CDN 并短路）：
//     1) 完整 CNAME 链逐跳命中 CDN 特征库
//     2) IP 落在 CDN 厂商网段库
//     3) HTTP 响应头（Server / CF-Ray / X-Cache / Via）
//     4) 多个公共 DNS 解析结果不一致（带同域豁免）
//   全不命中 → 视为真实 IP，参与 C 段聚合

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Result struct {
	Domain  string
	CNAME   string   // 链尾
	Chain   []string // 完整 CNAME 链
	TTL     uint32   // 各 DNS 结果中的最小 TTL
	IPs     []string
	IsCDN   bool
	Vendor  string
	Reason  string
	Headers map[string]string // Server / CF-Ray / X-Cache / Via 的原始值
}

func main() {
	domain := flag.String("d", "", "单个域名，例如 example.com")
	file := flag.String("f", "", "域名文件，一行一个")
	out := flag.String("o", "", "CSV 输出路径，例如 result.csv")
	threads := flag.Int("t", 8, "并发数")
	timeoutSec := flag.Int("timeout", 3, "单次 DNS 查询超时（秒）")
	ns := flag.String("ns", "", "自定义 DNS 服务器，逗号分隔，默认 223.5.5.5,119.29.29.29,114.114.114.114")
	top := flag.Int("top", 0, "C 段汇总只显示前 N 个，0 表示全部")
	ipdbPath := flag.String("ipdb", "", "外部 IP 段库文件，默认使用内置库")
	nohttp := flag.Bool("nohttp", false, "关闭 HTTP 响应头探测（默认开启）")
	httpTimeout := flag.Int("httptimeout", 8, "HTTP 探测超时（秒）")
	showHeaders := flag.Bool("headers", false, "显示实际抓到的 Server/CF-Ray/X-Cache/Via 头值")
	plainMode := flag.String("plain", "", "只输出结果便于管道串联：host=仅真实域名，ip=仅真实 IP")
	flag.Parse()

	stdinHosts := readStdinHosts(*domain != "" || *file != "")
	targets := collectTargets(*domain, *file, stdinHosts)
	if len(targets) == 0 {
		fmt.Println("没有输入目标。用法：")
		flag.Usage()
		os.Exit(1)
	}

	var servers []string
	if strings.TrimSpace(*ns) != "" {
		for _, s := range strings.Split(*ns, ",") {
			if v := strings.TrimSpace(s); v != "" {
				servers = append(servers, v)
			}
		}
	}

	db, err := NewIPDB(*ipdbPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载 IP 段库失败：%v\n", err)
		os.Exit(1)
	}

	var hc *HTTPOracle
	if !*nohttp {
		hc = NewHTTPOracle(time.Duration(*httpTimeout) * time.Second)
	}

	resolver := NewMultiResolver(servers, time.Duration(*timeoutSec)*time.Second)

	// -plain 模式下所有提示走 stderr，stdout 只留干净结果，避免污染下游管道
	logf := newLogger(*plainMode)
	logf("目标 %d 个，并发 %d，DNS 超时 %ds\n", len(targets), *threads, *timeoutSec)
	logf("IP 段库 %d 条，HTTP 头探测：%v\n", db.Size(), !*nohttp)

	results := scanAll(resolver, db, hc, targets, *threads, *showHeaders)

	if *plainMode != "" {
		printPlain(results, *plainMode)
	} else {
		printResults(results)
		summarize(results)
	}

	if *out != "" {
		if err := writeCSV(*out, results); err != nil {
			fmt.Fprintf(os.Stderr, "写 CSV 失败：%v\n", err)
		} else {
			logf("CSV 已写入 %s\n", *out)
		}
	}

	if *plainMode == "" {
		printAggregate(results, *top)
	}
}

// newLogger 按模式给出日志函数：表格模式写 stdout，管道模式写 stderr。
func newLogger(plain string) func(string, ...any) {
	if plain == "" {
		return func(f string, a ...any) { fmt.Printf(f, a...) }
	}
	return func(f string, a ...any) { fmt.Fprintf(os.Stderr, f, a...) }
}

// readStdinHosts 读取管道输入。
//
// 三个必须处理的现实情况：
//  1. 被 IDE / CI / 自动化工具以管道方式启动时，stdin 是「已连接但永不关闭」的管道，
//     直接 Scanner 会一直等 EOF 卡死。
//  2. 上游工具（subfinder）冷启动 + 联网查询，首行可能要几秒才吐出来。所以等待策略分两种：
//     命令行给了 -d/-f 时只等 1.2s（stdin 只是可选补充）；没有任何显式目标时等 10s（显然要靠管道）。
//  3. 读取 goroutine 与消费端不能各用一个 done channel，否则 done 会抢先于 lines 里的
//     缓冲数据被选中，只读到首行。这里只用一个 channel，读完 close，靠 channel 语义排空缓冲。
//
// 首行之后改成「行间空闲超时」：每收到一行重置 10s 计时，而不是整体 5s 截断——上游逐源返回时会有停顿。
func readStdinHosts(hasExplicit bool) []string {
	info, err := os.Stdin.Stat()
	if err != nil {
		return nil
	}
	// 字符设备 = 交互式终端，没有管道喂数据
	if info.Mode()&os.ModeCharDevice != 0 {
		return nil
	}

	lines := make(chan string, 1024)
	go func() {
		defer close(lines)
		sc := bufio.NewScanner(os.Stdin)
		sc.Buffer(make([]byte, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" {
				lines <- line
			}
		}
	}()

	firstWait := 90 * time.Second
	if hasExplicit {
		firstWait = 1200 * time.Millisecond
	} else {
		// 实测 subfinder 冷启动到首行约 22–24s，这里给足余量并明确提示，避免看起来像卡死
		fmt.Fprintf(os.Stderr, "等待 stdin 输入（最长 %ds；subfinder 冷启动约 20-25s）...\n", int(firstWait/time.Second))
	}

	var out []string
	select {
	case line, ok := <-lines:
		if !ok {
			return nil
		}
		out = append(out, line)
	case <-time.After(firstWait):
		return nil
	}

	// 逐行读，行与行之间空闲超过 45s 就收尾（上游逐源返回时会有较长停顿）
	idleWait := 45 * time.Second
	idle := time.NewTimer(idleWait)
	defer idle.Stop()
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				return out
			}
			out = append(out, line)
			if !idle.Stop() {
				select {
				case <-idle.C:
				default:
				}
			}
			idle.Reset(idleWait)
		case <-idle.C:
			return out
		}
	}
}

func collectTargets(domain, file string, stdinHosts []string) []string {
	var raw []string
	if domain != "" {
		raw = append(raw, domain)
	}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "打开域名文件失败：%v\n", err)
		} else {
			defer f.Close()
			sc := bufio.NewScanner(f)
			for sc.Scan() {
				raw = append(raw, sc.Text())
			}
		}
	}
	raw = append(raw, stdinHosts...)

	seen := make(map[string]struct{})
	var out []string
	for _, t := range raw {
		t = normalizeHost(t)
		if t == "" {
			continue
		}
		if _, ok := seen[t]; ok {
			continue
		}
		seen[t] = struct{}{}
		out = append(out, t)
	}
	return out
}

// normalizeHost 剥掉协议、路径、端口，只保留主机名。
func normalizeHost(in string) string {
	s := strings.TrimSpace(in)
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// 只剥离 "主机:端口" 形式，避免误伤 IPv6
	if i := strings.LastIndex(s, ":"); i >= 0 && !strings.Contains(s, "]") {
		if isAllDigits(s[i+1:]) {
			s = s[:i]
		}
	}
	return strings.ToLower(strings.TrimSuffix(s, "."))
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func scanAll(r *MultiResolver, db *IPDB, hc *HTTPOracle, targets []string, threads int, showHeaders bool) []Result {
	if threads < 1 {
		threads = 1
	}
	results := make([]Result, len(targets))
	sem := make(chan struct{}, threads)
	var wg sync.WaitGroup

	for i, t := range targets {
		wg.Add(1)
		go func(idx int, host string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = judge(r, db, hc, host, showHeaders)
		}(i, t)
	}
	wg.Wait()
	return results
}

func judge(r *MultiResolver, db *IPDB, hc *HTTPOracle, host string, showHeaders bool) Result {
	res := Result{Domain: host}

	// -headers 模式先探一次，保证即使维度一/二先命中、短路返回，也能看到原始头值
	var hv httpVerdict
	var hvDone bool
	if hc != nil && showHeaders {
		hv = hc.Check(host)
		hvDone = true
		res.Headers = hv.Headers
	}

	answers := r.QueryAll(host)

	// 合并 CNAME 链：多 DNS 通常一致，取最长的一条以保留更多跳点信息
	var chain []string
	for _, a := range answers {
		if len(a.Chain) > len(chain) {
			chain = a.Chain
		}
	}
	res.Chain = chain
	if len(chain) > 0 {
		res.CNAME = chain[len(chain)-1]
	}

	// TTL 取各服务商结果里的最小值，代表最短缓存窗口
	for _, a := range answers {
		if len(a.IPs) == 0 || a.TTL == 0 {
			continue
		}
		if res.TTL == 0 || a.TTL < res.TTL {
			res.TTL = a.TTL
		}
	}

	// 汇总所有 IP
	var allIPs []string
	for _, a := range answers {
		allIPs = append(allIPs, a.IPs...)
	}
	res.IPs = uniqSorted(allIPs)

	if len(res.IPs) == 0 {
		res.Reason = "解析失败或域名不存在"
		return res
	}

	// 维度一：完整 CNAME 链逐跳特征匹配
	if vendor, sig, _ := MatchCDNChain(res.Chain); vendor != "" {
		res.IsCDN = true
		res.Vendor = vendor
		if len(res.Chain) > 1 {
			res.Reason = fmt.Sprintf("CNAME 链（%d 跳）命中 %s (%s)", len(res.Chain), vendor, sig)
		} else {
			res.Reason = "CNAME 链命中 " + vendor + " (" + sig + ")"
		}
		return res
	}

	// 维度二：IP 落在已知 CDN 网段
	for _, ip := range res.IPs {
		if vendor := db.Lookup(ip); vendor != "" {
			res.IsCDN = true
			res.Vendor = vendor
			res.Reason = "IP " + ip + " 落在 " + vendor + " 网段"
			return res
		}
	}

	// 维度三：HTTP 响应头（Server / CF-Ray / X-Cache / Via）
	if hc != nil {
		if !hvDone {
			hv = hc.Check(host)
			hvDone = true
			if showHeaders {
				res.Headers = hv.Headers
			}
		}
		if hv.Vendor != "" {
			res.IsCDN = true
			res.Vendor = hv.Vendor
			res.Reason = hv.Reason
			return res
		}
	}

	// 维度四：多 DNS 解析不一致
	var sigs []string
	var validServers int
	for _, a := range answers {
		if len(a.IPs) == 0 {
			continue
		}
		validServers++
		sigs = append(sigs, signature(a.IPs))
	}
	if validServers >= 2 {
		distinct := uniqSorted(sigs)
		if len(distinct) > 1 {
			// 豁免：CNAME 链尾仍在目标自身的注册域内，更像自建负载均衡/多出口，不是第三方 CDN
			// 典型反例：www.pku.edu.cn → www.lb.pku.edu.cn，多 DNS 不一致但属于北大自己的 GSLB
			if len(res.Chain) > 0 && sameRegistrableDomain(host, res.Chain[len(res.Chain)-1]) {
				res.Reason = "多 DNS 不一致，但 CNAME 仍在自身域内（判为自建负载均衡）"
				return res
			}
			res.IsCDN = true
			res.Reason = fmt.Sprintf("多 DNS 解析不一致（%d 种结果）", len(distinct))
			return res
		}
	}

	res.Reason = "四维度均未命中 CDN 特征"
	return res
}

// sameRegistrableDomain 判断 target 是否落在 host 的注册域内。
// 取 host 的最后两段做保守判断（对 xxx.edu.cn 这类会取到 edu.cn，偏宽松，但对同一条链是安全的）。
func sameRegistrableDomain(host, target string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	target = strings.TrimSuffix(strings.ToLower(target), ".")
	if host == "" || target == "" || host == target {
		return host == target
	}
	if !strings.Contains(host, ".") {
		return false
	}
	parts := strings.Split(host, ".")
	base := strings.Join(parts[len(parts)-2:], ".")
	return target == base || strings.HasSuffix(target, "."+base)
}
