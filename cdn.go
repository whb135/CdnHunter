package main

import "strings"

// CDN CNAME 特征库
// 判定思路：域名的 CNAME 链命中以下任一后缀，即视为使用该 CDN。
// 后缀统一小写，匹配时对 CNAME 做 ToLower 后逐条 HasSuffix 比对。

type cdnSig struct {
	Name     string
	Suffixes []string
}

var cdnSignatures = []cdnSig{
	{"Cloudflare", []string{
		".cdn.cloudflare.net",
		".cloudflare.com",
		".cloudflare.net",
		".cloudflare.cn",
	}},
	{"Akamai", []string{
		".akamai.net",
		".akamaiedge.net",
		".akamaihd.net",
		".edgekey.net",
		".edgesuite.net",
		".akamai.com",
		".akamaistream.net",
	}},
	{"AWS CloudFront", []string{
		".cloudfront.net",
		".cloudfront.cn",
	}},
	{"Azure CDN", []string{
		".azureedge.net",
		".azurefd.net",
		".msecnd.net",
		".vo.llnwd.net",
	}},
	{"阿里云 CDN", []string{
		".kunlun.com",
		".kunluncc.com",
		".kunlunslb.com",
		".aliyuncdn.com",
		".alicdn.com",
	}},
	{"腾讯云 CDN", []string{
		".cdntip.com",
		".dnsv1.com",
		".tencent-cloud.net",
		".cdnqcloud.com",
		".myqcloud.com",
	}},
	{"百度云加速", []string{
		".yunjiasu-cdn.net",
		".baidubce.com",
		".bcebos.com",
	}},
	{"百度自建接入", []string{
		".shifen.com",
		".bdstatic.com",
		".bdurl.net",
	}},
	{"阿里自建缓存", []string{
		".tbcache.com",
	}},
	{"京东自建CDN", []string{
		".jcloud-cdn.com",
		".jcloudimg.com",
		".qianxun.com",
	}},
	{"腾讯云 EdgeOne", []string{
		".eo.dnse0.com",
		".edgeone.ai",
		".edgeone.com",
		".vedcdnlb.com",
	}},
	{"携程自建CDN", []string{
		".ctripgslb.net",
		".wsglb0.com",
	}},
	{"奇安信云WAF", []string{
		".qaxcloudwaf.com",
	}},
	{"网宿科技", []string{
		".wscdns.com",
		".wscloudcdn.com",
		".chinanetcdn.com",
		".ourwebcdn.com",
		".wscdns.net",
		".wswebpic.com",
		".51cdn.com",
	}},
	{"白山云", []string{
		".baishancloud.com",
		".bsgslb.cn",
		".bsclink.cn",
	}},
	{"七牛云", []string{
		".qiniudns.com",
		".qiniucdn.com",
		".qbox.me",
	}},
	{"又拍云", []string{
		".upaiyun.com",
		".upcdn.net",
		".upyun.com",
	}},
	{"金山云", []string{
		".ksyuncdn.com",
		".ksyun.com",
		".kscdn.com",
	}},
	{"华为云 CDN", []string{
		".hwclouds-dns.com",
		".huaweicloud-dns.com",
		".hwcdn.net",
	}},
	{"帝联科技", []string{
		".dnion.com",
		".fastcdn.com",
	}},
	{"蓝汛", []string{
		".chinacache.net",
		".ccindex.cn",
		".lxdns.com",
	}},
	{"加速乐", []string{
		".jiasule.com",
		".jsl.center",
	}},
	{"Fastly", []string{
		".fastly.net",
		".fastlylb.net",
	}},
	{"Google Cloud CDN", []string{
		".googleusercontent.com",
		".gvt1.com",
	}},
	{"Imperva / Incapsula", []string{
		".incapdns.net",
		".impervadns.net",
	}},
	{"Sucuri", []string{
		".sucuri.net",
	}},
	{"StackPath / MaxCDN", []string{
		".stackpathdns.com",
		".netdna-cdn.com",
		".netdna.com",
	}},
	{"CDN77", []string{
		".cdn77.org",
		".cdn77.net",
	}},
	{"KeyCDN", []string{
		".kxcdn.com",
	}},
	{"Bunny CDN", []string{
		".b-cdn.net",
	}},
	{"Gcore", []string{
		".gcdn.co",
	}},
	{"Yundun / 知道创宇", []string{
		".yundun.com",
		".yunaq.com",
	}},
	{"ChinaNet / 电信云堤", []string{
		".ctcdn.cn",
		".ctyuncdn.cn",
	}},
	{"联通沃云", []string{
		".wocdn.cn",
	}},
	{"移动云", []string{
		".cmecloud.cn",
		".chinamobile.com",
	}},
	{"UCloud", []string{
		".ucloud.cn",
		".ufileos.com",
	}},
	{"盛大 / 维络", []string{
		".vlike.com",
	}},
}

// MatchCDN 根据单个 CNAME 判断 CDN 厂商，未命中返回空。
func MatchCDN(cname string) (string, string) {
	if cname == "" {
		return "", ""
	}
	low := strings.ToLower(strings.TrimSuffix(cname, "."))
	for _, sig := range cdnSignatures {
		for _, s := range sig.Suffixes {
			if strings.HasSuffix(low, s) || strings.Contains(low, s+".") {
				return sig.Name, s
			}
		}
	}
	return "", ""
}

// MatchCDNChain 对完整 CNAME 链逐跳匹配，返回最早命中的一跳。
// 逐跳匹配的意义：很多站点第一跳是自己的业务子域（如 shop.example.com → shop.example.com.cdn-accel.aliyun.com），
// 只取最终一跳会漏掉中间跳上的厂商特征。
func MatchCDNChain(chain []string) (vendor, sig, hop string) {
	for _, h := range chain {
		if v, s := MatchCDN(h); v != "" {
			return v, s, h
		}
	}
	return "", "", ""
}
