package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

//go:embed ipdb.txt
var builtinIPDB string

type ipEntry struct {
	net    *net.IPNet
	vendor string
}

// IPDB 是 CDN 厂商的 IP 段库，用于第三维度判定：
// 域名解析出的 IP 落在已知 CDN 网段内，即使 CNAME 没有特征，也判为 CDN。
type IPDB struct {
	entries []ipEntry
}

func NewIPDB(externalPath string) (*IPDB, error) {
	db := &IPDB{}

	content := builtinIPDB
	if externalPath != "" {
		b, err := os.ReadFile(externalPath)
		if err != nil {
			return nil, fmt.Errorf("读取 IP 段库失败: %w", err)
		}
		content = string(b)
	}

	if err := db.load(content); err != nil {
		return nil, err
	}
	// 掩码越长越精确，优先匹配
	sort.Slice(db.entries, func(i, j int) bool {
		a, _ := db.entries[i].net.Mask.Size()
		b, _ := db.entries[j].net.Mask.Size()
		return a > b
	})
	return db, nil
}

func (db *IPDB) load(content string) error {
	sc := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for sc.Scan() {
		lineNo++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		_, ipNet, err := net.ParseCIDR(fields[0])
		if err != nil {
			return fmt.Errorf("IP 段库第 %d 行格式错误: %q", lineNo, fields[0])
		}
		db.entries = append(db.entries, ipEntry{
			net:    ipNet,
			vendor: strings.Join(fields[1:], " "),
		})
	}
	if len(db.entries) == 0 {
		return fmt.Errorf("IP 段库为空")
	}
	return nil
}

// Lookup 返回命中的厂商名，未命中返回空。
func (db *IPDB) Lookup(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	for _, e := range db.entries {
		if e.net.Contains(ip) {
			return e.vendor
		}
	}
	return ""
}

func (db *IPDB) Size() int { return len(db.entries) }
