package main

// 判定逻辑的回归测试。样本全部取自真实抓包（见 README 的实测记录），
// 目的是锁住「越精确越先判」的顺序：一旦有人把 X-Cache 之类的弱信号提前，
// 淘宝这类 Via 能精确认出厂商的站就会被降级成「缓存层」。

import (
	"net/http"
	"strings"
	"testing"
)

func hdr(kv ...string) http.Header {
	h := http.Header{}
	for i := 0; i+1 < len(kv); i += 2 {
		h.Set(kv[i], kv[i+1])
	}
	return h
}

func TestJudgeHeaders(t *testing.T) {
	cases := []struct {
		name       string
		h          http.Header
		wantVendor string
		wantSub    string // reason 必须包含的子串
	}{
		{
			name:       "Cloudflare CF-Ray",
			h:          hdr("Server", "cloudflare", "CF-Ray", "a5f847bf292f091d-LAX"),
			wantVendor: "Cloudflare",
			wantSub:    "Cf-Ray",
		},
		{
			// 淘宝实测：Server 是泛用的 Tengine，但 Via 里带 l2et 才是铁证
			name:       "阿里 Via 优先于 X-Cache",
			h:          hdr("Server", "Tengine", "X-Cache", "HIT TCP_MEM_HIT dirn:-2:-2", "Via", "cache35.l2et135-6[444,403,200-0,C]"),
			wantVendor: "阿里云CDN",
			wantSub:    "Via",
		},
		{
			// 京东实测：CNAME 之外，Via 里的 ORI-CLOUD 是第二证据
			name:       "京东 Via ORI-CLOUD",
			h:          hdr("Server", "nginx", "Via", "http/1.1 ORI-CLOUD-HB1-MIX-62 (jcs [cMsSfW])"),
			wantVendor: "京东自建CDN",
			wantSub:    "京东云节点标识",
		},
		{
			name:       "百度 BWS",
			h:          hdr("Server", "BWS/1.1"),
			wantVendor: "百度自建CDN",
			wantSub:    "bws",
		},
		{
			name:       "网宿 wswaf",
			h:          hdr("Server", "wswaf", "Via", "1.1 ID-7203207600205735 uproxy-4"),
			wantVendor: "网宿科技",
			wantSub:    "wswaf",
		},
		{
			// 12306 实测：只有 X-Cache 这一条弱证据，退化为缓存层
			name:       "仅 X-Cache 弱信号",
			h:          hdr("X-Cache", "HIT from cache.51cdn.com"),
			wantVendor: "缓存层(疑似CDN)",
			wantSub:    "X-Cache",
		},
		{
			// 普通自建站：nginx 不该被判成任何 CDN
			name:       "普通 nginx 站",
			h:          hdr("Server", "nginx", "X-Powered-By", "PHP/7.4"),
			wantVendor: "",
			wantSub:    "",
		},
		{
			// Tengine 是阿里系常见 Server，但自建站也用，不能单独当铁证
			name:       "仅 Tengine 降级为自建缓存层",
			h:          hdr("Server", "Tengine"),
			wantVendor: "阿里系Tengine",
			wantSub:    "自建缓存层",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			vendor, reason := judgeHeaders(c.h)
			if vendor != c.wantVendor {
				t.Fatalf("vendor = %q, want %q (reason=%q)", vendor, c.wantVendor, reason)
			}
			if c.wantSub != "" && !containsFoldStr(reason, c.wantSub) {
				t.Fatalf("reason = %q, want contains %q", reason, c.wantSub)
			}
		})
	}
}

func TestSnapshotHeaders(t *testing.T) {
	h := hdr(
		"Server", "cloudflare",
		"CF-Ray", "a5f847bf292f091d-LAX",
		"X-Cache", "HIT",
		"Via", "1.1 vegur",
	)
	snap := snapshotHeaders(h)
	want := map[string]string{
		"Server":  "cloudflare",
		"CF-Ray":  "a5f847bf292f091d-LAX",
		"X-Cache": "HIT",
		"Via":     "1.1 vegur",
	}
	for k, v := range want {
		if snap[k] != v {
			t.Fatalf("%s = %q, want %q", k, snap[k], v)
		}
	}

	empty := snapshotHeaders(hdr("Server", "nginx"))
	if empty["CF-Ray"] != "-" || empty["X-Cache"] != "-" {
		t.Fatalf("missing headers should be %q, got %#v", "-", empty)
	}
}

func containsFoldStr(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}
