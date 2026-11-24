package main

import (
	"crypto/tls"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPOracle 是第三维度判定：直接看响应头。
// DNS 层面看不出 CDN 的站点（边缘节点落在运营商机房、自建 anycast），
// 往往会在响应头里暴露真相。

type HTTPOracle struct {
	client *http.Client
}

type httpVerdict struct {
	Vendor  string
	Reason  string
	Headers map[string]string // 四个关键头的原始值，供 -headers 展示
}

func NewHTTPOracle(timeout time.Duration) *HTTPOracle {
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   timeout,
			KeepAlive: 10 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: timeout,
		// 测绘场景下目标证书常常不匹配域名，跳过校验是行业惯例（httpx -insecure 同理）
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    50,
	}
	return &HTTPOracle{
		client: &http.Client{
			Transport: transport,
			Timeout:   timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

// 关键头：Server / CF-Ray / X-Cache / Via。这四个是识别 CDN 最直接的证据面。
var keyHeaderNames = []string{"Server", "CF-Ray", "X-Cache", "Via"}

// 强信号头：出现即基本可确定该厂商。
// Weak=true 的是「缓存层证据」：只证明响应来自某个缓存节点，不一定是第三方 CDN
// （自建 nginx proxy_cache / varnish 也会发 X-Cache），所以统一排在 strong 之后，reason 里注明。
var strongHeaderRules = []struct {
	Header string
	Vendor string
	Weak   bool
}{
	{"Cf-Ray", "Cloudflare", false},
	{"X-Akamai-Transformed", "Akamai", false},
	{"X-Akamai-Request-Id", "Akamai", false},
	{"X-Served-By", "Fastly", false},
	{"X-Cache-Hits", "Fastly", false},
	{"Ali-Swift", "阿里云CDN", false},
	{"Ali-Swift-Global-Savetime", "阿里云CDN", false},
	{"X-Swift-Savetime", "阿里云CDN", false},
	{"X-Swift-Cachetime", "阿里云CDN", false},
	{"X-Ali-Cdn", "阿里云CDN", false},
	{"X-Tengine-Error", "阿里系Tengine", false},
	{"X-Cdn", "CDN", false},
	{"X-Edge-Location", "CDN", false},
	{"X-Cache", "缓存层(疑似CDN)", true},
	{"X-Cache-Status", "缓存层(疑似CDN)", true},
	{"X-Cache-Lookup", "缓存层(疑似CDN)", true},
}

// Server 头规则。Weak 项统一排最后，避免把自建 Tengine/Varnish 误判成厂商 CDN。
var serverVendorRules = []struct {
	Contains string
	Vendor   string
	Weak     bool
}{
	{"cloudflare", "Cloudflare", false},
	{"akamai", "Akamai", false},
	{"cachefly", "CacheFly", false},
	{"incapsula", "Imperva", false},
	{"sucuri", "Sucuri", false},
	{"awselb", "AWS-ELB", false},
	{"cloudfront", "AWS-CloudFront", false},
	{"bfe", "百度自建CDN", false},
	{"bws", "百度自建CDN", false},
	{"yunjiasu", "百度云加速", false},
	{"jiasule", "加速乐", false},
	{"wswaf", "网宿科技", false},
	{"tengine", "阿里系Tengine", true},
	{"varnish", "缓存层(疑似CDN)", true},
	{"squid", "缓存层(疑似CDN)", true},
}

func (o *HTTPOracle) Check(host string) httpVerdict {
	// 先试 https，失败退 http
	for _, scheme := range []string{"https", "http"} {
		url := scheme + "://" + host + "/"
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		req.Header.Set("Accept", "*/*")

		resp, err := o.client.Do(req)
		if err != nil {
			continue
		}
		// 只读头，立即关掉 body
		resp.Body.Close()

		snap := snapshotHeaders(resp.Header)
		if v, r := judgeHeaders(resp.Header); v != "" {
			return httpVerdict{Vendor: v, Reason: r, Headers: snap}
		}
		// 有响应但无 CDN 特征，说明是直连
		return httpVerdict{Headers: snap}
	}
	return httpVerdict{}
}

// snapshotHeaders 抓四个关键头的原始值，空值统一记 "-"。
func snapshotHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(keyHeaderNames))
	for _, k := range keyHeaderNames {
		v := h.Get(k)
		if v == "" {
			out[k] = "-"
			continue
		}
		out[k] = trimVal(v, 48)
	}
	return out
}

// judgeHeaders 按「越精确越先判」的顺序过四个证据面：
// 厂商专属头 → Server 强规则 → Via → 缓存层弱信号。
// 弱信号必须最后判，否则会把 Via/Server 能精确识别的厂商降级成「缓存层」。
func judgeHeaders(h http.Header) (string, string) {
	// 第一轮：厂商专属强信号头（CF-Ray、X-Akamai-*、Ali-Swift-* 等）
	for _, rule := range strongHeaderRules {
		if rule.Weak {
			continue
		}
		if val := h.Get(rule.Header); val != "" {
			return rule.Vendor, "响应头 " + rule.Header + " → " + rule.Vendor
		}
	}

	// 第二轮：Server 头，强规则立即返回，弱规则先记下
	server := strings.ToLower(h.Get("Server"))
	var weakVendor, weakReason string
	for _, rule := range serverVendorRules {
		if !strings.Contains(server, rule.Contains) {
			continue
		}
		if rule.Weak {
			if weakVendor == "" {
				weakVendor = rule.Vendor
				weakReason = "Server 头=" + trimVal(server, 32) + " → 自建缓存层"
			}
			continue
		}
		return rule.Vendor, "Server 头含 " + rule.Contains
	}

	// 第三轮：Via 头
	via := strings.ToLower(h.Get("Via"))
	if via != "" {
		switch {
		case strings.Contains(via, "kunlun"), strings.Contains(via, "ens-cache"),
			strings.Contains(via, "l2et"), strings.Contains(via, "swift"):
			return "阿里云CDN", "Via 头含阿里边缘节点标识"
		case strings.Contains(via, "akamai"):
			return "Akamai", "Via 头含 akamai 标识"
		case strings.Contains(via, "cloudfront"):
			return "AWS-CloudFront", "Via 头含 cloudfront 标识"
		case strings.Contains(via, "google"):
			return "Google CDN", "Via 头含 google 标识"
		case strings.Contains(via, "ori-cloud"):
			return "京东自建CDN", "Via 头含京东云节点标识"
		case strings.Contains(via, "cdn"):
			return "CDN", "Via 头含 cdn 标识"
		case strings.Contains(via, "trafficserver"), strings.Contains(via, "ats"):
			if weakVendor == "" {
				weakVendor = "缓存层(疑似CDN)"
				weakReason = "Via 头含 Apache Traffic Server 标识"
			}
		}
	}

	// 第四轮：缓存层弱信号头（X-Cache 系列）
	for _, rule := range strongHeaderRules {
		if !rule.Weak {
			continue
		}
		if val := h.Get(rule.Header); val != "" {
			return rule.Vendor, "响应头 " + rule.Header + "=" + trimVal(val, 32) + " → 来自缓存层"
		}
	}

	if weakVendor != "" {
		return weakVendor, weakReason
	}
	return "", ""
}

// trimVal 把过长的头值截断，避免撑坏表格。
func trimVal(v string, max int) string {
	if len(v) > max {
		return v[:max] + "..."
	}
	return v
}
