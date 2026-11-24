package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func printResults(results []Result) {
	fmt.Printf("\n%s %s %s %s %s\n", pad("DOMAIN", 34), pad("TYPE", 6), pad("VENDOR", 17), pad("TTL", 6), "IPS / REASON")
	fmt.Println(strings.Repeat("-", 112))
	for _, r := range results {
		mark := "REAL"
		if r.IsCDN {
			mark = "CDN"
		}
		vendor := r.Vendor
		if vendor == "" {
			vendor = "-"
		}
		ttl := "-"
		if r.TTL > 0 {
			ttl = strconv.FormatUint(uint64(r.TTL), 10)
		}
		note := joinIPs(r.IPs)
		if r.IsCDN {
			note = r.Reason
		}
		dom := r.Domain
		if len(dom) > 33 {
			dom = dom[:30] + "..."
		}
		fmt.Printf("%s %s %s %s %s\n", pad(dom, 34), pad(mark, 6), pad(vendor, 17), pad(ttl, 6), note)

		// 完整 CNAME 链单独一行，这是这版相对 net.Resolver 的核心增量
		if len(r.Chain) > 0 {
			fmt.Printf("%s   └ %s\n", strings.Repeat(" ", 34), joinChain(r.Chain))
		}

		// -headers 模式：把实际抓到的四个头原样亮出来
		if len(r.Headers) > 0 {
			fmt.Printf("%s   H> %s\n", strings.Repeat(" ", 34), formatHeaders(r.Headers))
		}
	}
	fmt.Println()
}

func formatHeaders(m map[string]string) string {
	parts := make([]string, 0, len(keyHeaderNames))
	for _, k := range keyHeaderNames {
		v := m[k]
		if v == "" {
			v = "-"
		}
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " | ")
}

// displayWidth 按终端显示宽度算长度：ASCII 记 1，其它（中文等）记 2。
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		if r < 128 {
			w++
		} else {
			w += 2
		}
	}
	return w
}

func pad(s string, width int) string {
	n := width - displayWidth(s)
	if n <= 0 {
		return s
	}
	return s + strings.Repeat(" ", n)
}

func joinChain(chain []string) string {
	return strings.Join(chain, " → ")
}

func writeCSV(path string, results []Result) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// UTF-8 BOM，避免 Excel 打开乱码
	if _, err := f.WriteString("\xEF\xBB\xBF"); err != nil {
		return err
	}

	w := csv.NewWriter(f)
	defer w.Flush()

	header := []string{"domain", "is_cdn", "vendor", "reason", "cname", "cname_chain", "ttl_min", "server", "cf_ray", "x_cache", "via", "ips", "c_segments"}
	if err := w.Write(header); err != nil {
		return err
	}
	for _, r := range results {
		segs := make([]string, 0, len(r.IPs))
		for _, ip := range r.IPs {
			if c := C24(ip); c != "" {
				segs = append(segs, c)
			}
		}
		segs = uniqSorted(segs)

		ttl := ""
		if r.TTL > 0 {
			ttl = strconv.FormatUint(uint64(r.TTL), 10)
		}

		h := r.Headers
		if h == nil {
			h = map[string]string{}
		}

		if err := w.Write([]string{
			r.Domain,
			strconv.FormatBool(r.IsCDN),
			r.Vendor,
			r.Reason,
			r.CNAME,
			strings.Join(r.Chain, " "),
			ttl,
			h["Server"],
			h["CF-Ray"],
			h["X-Cache"],
			h["Via"],
			strings.Join(r.IPs, " "),
			strings.Join(segs, " "),
		}); err != nil {
			return err
		}
	}
	return w.Error()
}

// printAggregate 只对判为真实 IP 的目标聚合 C 段，这是本工具的核心产出。
func printAggregate(results []Result, top int) {
	var realIPs []string
	var realCount int
	for _, r := range results {
		if r.IsCDN || len(r.IPs) == 0 {
			continue
		}
		realCount++
		realIPs = append(realIPs, r.IPs...)
	}
	if len(realIPs) == 0 {
		fmt.Println("没有可用于 C 段聚合的真实 IP（全部判定为 CDN 或解析失败）")
		return
	}

	segs, order := aggregateC(realIPs)
	if top > 0 && len(order) > top {
		order = order[:top]
	}

	fmt.Printf("\n真实资产 C 段（来自 %d 个非 CDN 域名 / 共 %d 个 IP）\n", realCount, len(uniqSorted(realIPs)))
	fmt.Println(strings.Repeat("-", 70))
	fmt.Printf("%-20s %-8s %s\n", "C-SEGMENT", "IP数", "IP")
	for _, s := range order {
		fmt.Printf("%-20s %-8d %s\n", s, len(segs[s]), joinIPs(segs[s]))
	}
	fmt.Println()
	fmt.Println("提示：C 段是资产测绘的起点而非结论，段内主机仍需逐台确认归属。")
}

// printPlain 输出机器可读结果：ip=只出真实 IP（去重排序），host=只出真实域名。
// 用于 `subfinder | cdnhunter -plain ip | httpx` 这类管道串联。
func printPlain(results []Result, mode string) {
	switch strings.ToLower(mode) {
	case "ip":
		var ips []string
		for _, r := range results {
			if r.IsCDN || len(r.IPs) == 0 {
				continue
			}
			ips = append(ips, r.IPs...)
		}
		for _, ip := range uniqSorted(ips) {
			fmt.Println(ip)
		}
	case "host", "domain":
		for _, r := range results {
			if r.IsCDN || len(r.IPs) == 0 {
				continue
			}
			fmt.Println(r.Domain)
		}
	default:
		fmt.Fprintf(os.Stderr, "未知的 -plain 值：%s（可用 host / ip）\n", mode)
	}
}

func summarize(results []Result) {
	var cdn, real, fail int
	for _, r := range results {
		switch {
		case len(r.IPs) == 0 && !r.IsCDN:
			fail++
		case r.IsCDN:
			cdn++
		default:
			real++
		}
	}
	fmt.Printf("统计：总数 %d    CDN %d    真实 %d    无结果 %d\n", len(results), cdn, real, fail)
}
