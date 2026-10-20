"""公开搜索直达：为目标生成常用搜索入口（纯深链接，不做任何自动抓取）。

微信 / QQ 等封闭生态无法自动探测；本模块只帮用户"一键跳到"公开搜索页手动查，
并为电话/IP/域名/URL 提供对应的公开情报平台入口。
"""

from __future__ import annotations

from urllib.parse import quote, quote_plus


def build_search_links(kind: str, target: str) -> list[dict]:
    q = quote_plus((target or "").strip())
    if not q:
        return []
    if kind in ("breach", "email"):
        return []
    raw = quote((target or "").strip(), safe="")
    links: list[dict] = [
        {"name": "百度", "url": f"https://www.baidu.com/s?wd={q}"},
        {"name": "必应", "url": f"https://www.bing.com/search?q={q}"},
    ]
    if kind == "phone":
        links += [
            {"name": "百度·骚扰/标记", "url": f"https://www.baidu.com/s?wd={q}%20%E9%AA%9A%E6%89%B0"},
            {"name": "360 号码查询", "url": "https://cx.shouji.360.cn/"},
            {"name": "12321 举报中心", "url": "https://www.12321.cn/"},
            {"name": "公安部网络举报", "url": "https://cyberpolice.mps.gov.cn/"},
        ]
    elif kind == "ip":
        links += [
            {"name": "微步在线", "url": f"https://x.threatbook.com/v5/ip/{raw}"},
            {"name": "Shodan", "url": f"https://www.shodan.io/host/{raw}"},
            {"name": "urlscan", "url": f"https://urlscan.io/search/#{raw}"},
            {"name": "Censys", "url": f"https://search.censys.io/hosts/{raw}"},
            {"name": "奇安信威胁情报", "url": "https://ti.qianxin.com/"},
        ]
    elif kind == "domain":
        links += [
            {"name": "crt.sh 证书", "url": f"https://crt.sh/?q={q}"},
            {"name": "urlscan", "url": f"https://urlscan.io/search/#domain%3A{raw}"},
            {"name": "站长之家 WHOIS", "url": f"https://whois.chinaz.com/{raw}"},
            {"name": "站长工具 DNS", "url": f"https://tool.chinaz.com/dns/?type=1&host={raw}"},
        ]
    elif kind == "url":
        links += [
            {"name": "urlscan 检索", "url": f"https://urlscan.io/search/#{q}"},
            {"name": "urlscan 截图", "url": f"https://urlscan.io/liveshot/?url={q}"},
            {"name": "VirusTotal 检索", "url": f"https://www.virustotal.com/gui/search?query={q}"},
            {"name": "微步在线 URL 检测", "url": "https://x.threatbook.com/v5/url"},
        ]
    elif kind in ("username", "user"):
        links += [
            {"name": "搜狗微信（公众号 / 文章）", "url": f"https://weixin.sogou.com/weixin?type=2&query={q}"},
            {"name": "微博", "url": f"https://s.weibo.com/user?q={q}"},
            {"name": "知乎", "url": f"https://www.zhihu.com/search?type=people&q={q}"},
            {"name": "贴吧", "url": f"https://tieba.baidu.com/f/search/res?qw={q}"},
            {"name": "GitHub", "url": f"https://github.com/search?q={q}"},
            {"name": "搜狗", "url": f"https://www.sogou.com/web?query={q}"},
            {"name": "360 搜索", "url": f"https://www.so.com/s?q={q}"},
            {"name": "安全社区（先知）", "url": f"https://xz.aliyun.com/search?keyword={q}"},
        ]
    elif kind == "mailbox":
        links += [
            {"name": "搜狗", "url": f"https://www.sogou.com/web?query={q}"},
            {"name": "GitHub 搜索", "url": f"https://github.com/search?q={q}"},
            {"name": "12321 举报中心", "url": "https://www.12321.cn/"},
            {"name": "网络违法犯罪举报", "url": "https://cyberpolice.mps.gov.cn/"},
        ]
    return links
