package main

// 用 miekg/dns 自己构造查询，替代 net.Resolver。
// 标准库 LookupCNAME 只返回最终一跳规范名，拿不到中间跳、也拿不到 TTL；
// 资产测绘里这两样都有用：中间跳常常才暴露 CDN 特征，TTL 反映调度频率。

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const maxCNAMEHops = 10

// IPRecord 是一条 A 记录及其 TTL。
type IPRecord struct {
	IP  string
	TTL uint32
}

// ChainResult 是一次完整解析的产物。
type ChainResult struct {
	Chain  []string   // CNAME 每一跳，从输入域名的下一跳开始，按解析顺序
	IPs    []IPRecord // 最终解析出的 A 记录
	MinTTL uint32     // 链上所有记录（CNAME + A）的最小 TTL
	MaxTTL uint32
	Rcode  int
	Hops   int // 实际发起的查询轮数
}

func (r *ChainResult) touchTTL(ttl uint32) {
	if ttl == 0 {
		return
	}
	if r.MinTTL == 0 || ttl < r.MinTTL {
		r.MinTTL = ttl
	}
	if ttl > r.MaxTTL {
		r.MaxTTL = ttl
	}
}

// QueryChain 向指定 DNS 服务器查询 host，逐跳跟随 CNAME 直到拿到 A 记录。
func QueryChain(server, host string, timeout time.Duration) (*ChainResult, error) {
	addr := server
	if _, _, err := net.SplitHostPort(server); err != nil {
		addr = net.JoinHostPort(server, "53")
	}

	res := &ChainResult{}
	current := dns.Fqdn(host)
	visited := map[string]struct{}{strings.ToLower(current): {}}

	for hop := 0; hop < maxCNAMEHops; hop++ {
		res.Hops = hop + 1

		m := new(dns.Msg)
		m.SetQuestion(current, dns.TypeA)
		m.RecursionDesired = true
		m.SetEdns0(1232, false)

		resp, err := exchange(addr, m, timeout)
		if err != nil {
			// 已经拿到部分结果就返回，不整体失败
			if len(res.IPs) > 0 || len(res.Chain) > 0 {
				return res, nil
			}
			return res, fmt.Errorf("查询 %s 失败：%w", current, err)
		}
		res.Rcode = resp.Rcode

		var next string
		var gotA bool

		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.CNAME:
				owner := strings.TrimSuffix(v.Hdr.Name, ".")
				target := strings.TrimSuffix(v.Target, ".")
				// 只把「当前节点发出」的跳转作为下一轮查询目标，避免把整链重复跟随
				if next == "" && strings.EqualFold(owner, strings.TrimSuffix(current, ".")) {
					next = target
				}
				if target != "" && !containsFold(res.Chain, target) {
					res.Chain = append(res.Chain, target)
				}
				res.touchTTL(v.Hdr.Ttl)
			case *dns.A:
				owner := strings.TrimSuffix(v.Hdr.Name, ".")
				// 递归响应里 A 记录的 owner 是链尾；也兼容只查一跳时 owner 就是当前域名
				if ownerMatches(owner, current, res.Chain) {
					gotA = true
					ip := v.A.String()
					if !hasIPRecord(res.IPs, ip) {
						res.IPs = append(res.IPs, IPRecord{IP: ip, TTL: v.Hdr.Ttl})
					}
					res.touchTTL(v.Hdr.Ttl)
				}
			}
		}

		// 已经拿到 A 记录，说明递归服务器把整条链都展开了，不必再逐跳跟
		if gotA {
			break
		}
		if next == "" {
			break
		}
		key := strings.ToLower(next)
		if _, ok := visited[key]; ok {
			break // CNAME 环路
		}
		visited[key] = struct{}{}
		current = dns.Fqdn(next)
	}

	return res, nil
}

// exchange 先走 UDP，截断或失败时退 TCP 重试一次。
func exchange(addr string, m *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	uc := &dns.Client{Net: "udp", Timeout: timeout, UDPSize: 1232}
	resp, _, uerr := uc.Exchange(m, addr)
	if uerr == nil && resp != nil && !resp.Truncated {
		return resp, nil
	}

	tc := &dns.Client{Net: "tcp", Timeout: timeout}
	resp2, _, terr := tc.Exchange(m, addr)
	if terr != nil {
		if uerr != nil {
			return nil, uerr
		}
		return nil, terr
	}
	if resp2 == nil {
		return nil, fmt.Errorf("空响应")
	}
	return resp2, nil
}

// ownerMatches 判断 A 记录的 owner 是否属于本次解析的链上节点。
func ownerMatches(owner, current string, chain []string) bool {
	if strings.EqualFold(owner, strings.TrimSuffix(current, ".")) {
		return true
	}
	return containsFold(chain, owner)
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func hasIPRecord(list []IPRecord, ip string) bool {
	for _, v := range list {
		if v.IP == ip {
			return true
		}
	}
	return false
}
