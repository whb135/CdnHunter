package main

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// C24 把 IPv4 转成 /24 网段字符串，非法地址返回空。
func C24(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil || ip.To4() == nil {
		return ""
	}
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
}

// aggregateC 汇总所有 IP 的 C 段，返回按出现次数倒序的列表。
func aggregateC(ips []string) (map[string][]string, []string) {
	m := make(map[string][]string)
	for _, ip := range ips {
		c := C24(ip)
		if c == "" {
			continue
		}
		m[c] = append(m[c], ip)
	}
	order := make([]string, 0, len(m))
	for k := range m {
		order = append(order, k)
	}
	sort.Slice(order, func(i, j int) bool {
		if len(m[order[i]]) != len(m[order[j]]) {
			return len(m[order[i]]) > len(m[order[j]])
		}
		return order[i] < order[j]
	})
	// 段内 IP 去重排序
	for k, v := range m {
		m[k] = uniqSorted(v)
	}
	return m, order
}

func joinIPs(ips []string) string {
	if len(ips) == 0 {
		return "-"
	}
	return strings.Join(ips, " ")
}
