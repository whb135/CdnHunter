package main

import (
	"sort"
	"strings"
	"sync"
	"time"
)

// MultiResolver 用多个公共 DNS 分别解析同一域名，用于识别 CDN。
// 单点解析只能拿到就近节点的 IP，多地结果不一致往往意味着调度型 CDN。
type MultiResolver struct {
	servers []string
	timeout time.Duration
}

func NewMultiResolver(servers []string, timeout time.Duration) *MultiResolver {
	if len(servers) == 0 {
		servers = []string{"223.5.5.5", "119.29.29.29", "114.114.114.114"}
	}
	return &MultiResolver{servers: servers, timeout: timeout}
}

// dnsAnswer 是一台 DNS 服务器的解析结果。
type dnsAnswer struct {
	Server string
	IPs    []string
	CNAME  string   // 链尾（最终规范名）
	Chain  []string // 完整 CNAME 链
	TTL    uint32   // 本次解析的最小 TTL
	Err    error
}

// QueryAll 对所有 DNS 服务器并发解析一个域名。
func (m *MultiResolver) QueryAll(host string) []dnsAnswer {
	answers := make([]dnsAnswer, len(m.servers))
	var wg sync.WaitGroup

	for i, srv := range m.servers {
		wg.Add(1)
		go func(idx int, server string) {
			defer wg.Done()

			cr, err := QueryChain(server, host, m.timeout)
			if err != nil || cr == nil {
				answers[idx] = dnsAnswer{Server: server, Err: err}
				return
			}

			var ips []string
			for _, rec := range cr.IPs {
				ips = append(ips, rec.IP)
			}
			ips = uniqSorted(ips)

			cname := ""
			if len(cr.Chain) > 0 {
				cname = cr.Chain[len(cr.Chain)-1]
			}

			answers[idx] = dnsAnswer{
				Server: server,
				IPs:    ips,
				CNAME:  cname,
				Chain:  cr.Chain,
				TTL:    cr.MinTTL,
			}
		}(i, srv)
	}
	wg.Wait()
	return answers
}

func uniqSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// signature 把一组 IP 压成可比较的字符串，用于判断两次解析是否一致。
func signature(ips []string) string {
	return strings.Join(ips, ",")
}
