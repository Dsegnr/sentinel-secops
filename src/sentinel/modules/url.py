"""URL 安全检查：结构混淆特征 / 重定向链 / 域名属性 / 深度分析入口。

只对目标 URL 本身做 GET（跟随重定向），不向任何第三方服务提交；
高级分析（urlscan / VT）以手动深链形式提供。
"""

from __future__ import annotations

import re
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit

from ..core import netintel
from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "dwz.cn", "url.cn", "t.cn",
    "suo.im", "sina.lt", "u6.gg", "urlz.fr", "rb.gy", "shrtco.de",
}

_SUSPICIOUS_TLDS = {
    "zip", "mov", "tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click",
    "link", "loan", "win", "men", "review", "date", "faith", "party", "download",
    "stream", "racing", "trade", "buzz", "rest", "monster", "quest", "cyou",
}

_BRANDS = [
    "alipay", "taobao", "tmall", "jd", "wechat", "weixin", "qq", "tencent", "baidu",
    "douyin", "xiaohongshu", "icbc", "ccb", "abc", "boc", "cmbchina", "unionpay",
    "apple", "microsoft", "google", "amazon", "paypal", "netflix", "binance", "okx",
    "coinbase", "metamask", "steam", "aliyun", "huawei", "xiaomi", "pinduoduo",
]

_MAX_HOPS = 6
_BODY_SNIFF = 100_000


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _script_of(ch: str) -> str:
    if not ch.isalpha():
        return ""
    name = unicodedata.name(ch, "")
    for script in ("CYRILLIC", "GREEK", "LATIN", "CJK", "ARABIC", "HEBREW"):
        if script in name:
            return script
    return ""


def _host_scripts(host: str) -> set[str]:
    return {s for s in (_script_of(c) for c in host) if s}


def analyze_structure(raw_url: str) -> dict:
    """离线结构分析：返回 {url, host, host_display, issues[]}。"""
    text = (raw_url or "").strip()
    issues: list[str] = []
    if not re.match(r"^[a-z][a-z0-9+.-]*://", text, re.I):
        text = "http://" + text
    try:
        parts = urlsplit(text)
    except Exception:  # noqa: BLE001
        return {"url": text, "host": "", "host_display": "", "issues": ["URL 结构无法解析"]}
    host = (parts.hostname or "").lower()
    host_display = host
    try:
        host_display = host.encode("ascii").decode("idna")
    except Exception:  # noqa: BLE001
        pass

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
        issues.append("宿主为 IP 地址（正常站点很少直接使用 IP）")
    if "xn--" in host:
        issues.append(f"域名含 punycode 编码（显示为 {host_display}，注意同形异义字符）")
    scripts = _host_scripts(host_display)
    if "LATIN" in scripts and ({"CYRILLIC", "GREEK"} & scripts):
        issues.append("域名混合了拉丁与西里尔/希腊字母（典型同形异义钓鱼特征）")
    if parts.port and parts.port not in (80, 443):
        issues.append(f"使用非标准端口 {parts.port}")
    if "@" in (parts.netloc or ""):
        issues.append("URL 中含 @ 混淆（@ 前的部分会被浏览器忽略）")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in _SUSPICIOUS_TLDS:
        issues.append(f"可疑顶级域 .{tld}（钓鱼/垃圾站高发）")
    labels = host.split(".")
    if host.count(".") >= 4:
        issues.append(f"子域层级过深（{host.count('.')} 层），常用于伪造信任感")
    for label in labels[:-2]:
        if label in _BRANDS:
            issues.append(f"子域中包含品牌名 '{label}'（常见伪造手法）")
            break
    core_label = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    for brand in _BRANDS:
        if core_label == brand:
            break
        if len(core_label) >= 4 and _levenshtein(core_label, brand) <= 1:
            issues.append(f"主域名 '{core_label}' 与知名品牌 '{brand}' 高度相似（疑似仿冒）")
            break
    if len(text) > 200:
        issues.append(f"URL 超长（{len(text)} 字符）")
    if text.count("%") >= 8:
        issues.append("包含大量百分号编码")
    if re.search(r"\.(exe|scr|bat|cmd|msi|vbs|js|jar|apk)(\?|#|$)", parts.path, re.I):
        issues.append("路径以可执行文件 / 安装包结尾")
    if unquote(parts.path).lower().endswith((".exe", ".scr", ".vbs")):
        issues.append("路径编码后可执行文件（双重编码混淆）")
    return {"url": text, "host": host, "host_display": host_display, "issues": issues}


def _follow_chain(url: str, client: HttpClient) -> tuple[list[dict], str, int | None, str]:
    """手动跟随重定向（GET，限 6 跳，只读正文前 100KB）。返回 (链, 最终URL, 最终状态码, 页面标题)。"""
    chain: list[dict] = []
    current = url
    final_status: int | None = None
    title = ""
    for _ in range(_MAX_HOPS + 1):
        resp = client.get(current, allow_redirects=False, stream=True, timeout=8, retries=0)
        status = resp.status_code
        location = resp.headers.get("location")
        chain.append({"url": current, "status": status, "location": location or ""})
        if status >= 300 and location:
            try:
                body = resp.raw.read(_BODY_SNIFF, decode_content=True) or b""
            except Exception:  # noqa: BLE001
                body = b""
            finally:
                resp.close()
            current = urljoin(current, location)
            continue
        # 终页：读前 100KB 提取标题
        try:
            chunk = resp.raw.read(_BODY_SNIFF, decode_content=True) or b""
            text = chunk.decode("utf-8", errors="ignore")
            match = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
            if match:
                title = " ".join(match.group(1).split())[:120]
        except Exception:  # noqa: BLE001
            pass
        finally:
            resp.close()
        final_status = status
        break
    return chain, current, final_status, title


def triage(target: str, client: HttpClient) -> TriageReport:
    structure = analyze_structure(target)
    rep = TriageReport(kind="url", target=structure["url"])
    issues = list(structure["issues"])
    host = structure["host"]
    if not host:
        rep.add("解析", "URL 无法解析", Confidence.UNAVAILABLE, "内置")
        return rep

    rep.add("宿主", structure["host_display"], Confidence.CONFIRMED, "内置解析")

    # 短链展开 + 重定向链
    source_ok = True
    try:
        chain, final_url, final_status, title = _follow_chain(structure["url"], client)
        hops = len(chain) - 1
        rep.add("重定向链", f"{hops} 跳：" + " → ".join(str(c["status"]) for c in chain), Confidence.CONFIRMED, "HTTP 直连")
        rep.add("最终地址", final_url[:160], Confidence.CONFIRMED, "HTTP 直连")
        if title:
            rep.add("页面标题", title, Confidence.LIKELY, "HTTP 直连")
        if final_status is not None:
            rep.add("最终状态", str(final_status), Confidence.CONFIRMED, "HTTP 直连")
        if host in _SHORTENERS and hops >= 1:
            rep.add("短链", f"是（已展开 {hops} 跳）", Confidence.CONFIRMED, "内置规则")
        if any(str(c["url"]).startswith("https://") and str(c["location"]).startswith("http://") for c in chain):
            rep.add("HTTPS 降级", "重定向中出现 HTTPS → HTTP 降级", Confidence.LIKELY, "内置规则")
            issues.append("重定向中 HTTPS 降级")
        final_host = (urlsplit(final_url).hostname or "").lower()
    except Exception as exc:  # noqa: BLE001
        source_ok = False
        final_host = host
        rep.add("重定向链", f"不可达：{str(exc)[:90]}", Confidence.UNAVAILABLE, "HTTP 直连")

    # 域名属性（对最终宿主所在注册域）
    if final_host and not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", final_host):
        reg = netintel.registrable_domain(final_host)
        try:
            records = netintel.resolve_records(reg, timeout=4.0, types=("A", "AAAA"))
            if records.get("_errors", {}).get("A") == "NXDOMAIN":
                rep.add("域名状态", f"{reg} NXDOMAIN（域名不存在）", Confidence.LIKELY, "DNS")
                issues.append("域名不存在（NXDOMAIN）")
        except Exception:  # noqa: BLE001
            pass
        try:
            who = netintel.whois_lookup(reg, timeout=6.0)
            if who.get("created"):
                age = netintel.fmt_age(who["created"])
                rep.add("域名注册时间", f"{who['created']}" + (f"（约 {age}）" if age else ""), Confidence.LIKELY, "WHOIS")
                age_match = re.search(r"约 (\d+) 天", age or "")
                if age_match and int(age_match.group(1)) < 90:
                    issues.append("域名注册不足 90 天（钓鱼常用新域名）")
            if who.get("registrar"):
                rep.add("注册商", who["registrar"], Confidence.LIKELY, "WHOIS")
        except Exception:  # noqa: BLE001
            pass

    if issues:
        rep.add("风险特征", "；".join(f"⚠ {i}" for i in issues), Confidence.LIKELY, "内置规则")
    else:
        rep.add("风险特征", "未发现明显结构风险（不代表安全）", Confidence.UNVERIFIED, "内置规则")
    if issues:
        rep.add("综合判定", f"发现 {len(issues)} 项风险特征，建议不要直接打开/输入任何凭据；可先交给沙箱或 urlscan 查看。", Confidence.LIKELY, "内置规则")
    else:
        rep.add("综合判定", "未发现明显风险特征；如需更权威判定，可用下方入口提交沙箱分析。", Confidence.UNVERIFIED, "内置规则")
    rep.sources.append(SourceResult("结构分析", True, "离线规则"))
    rep.sources.append(SourceResult("HTTP 直连", source_ok, "重定向链与标题"))
    rep.note("本工具不把目标 URL 提交给任何第三方；urlscan / VirusTotal 入口为手动深链。")
    return rep


def offline_flags(url: str) -> list[str]:
    """给其他模块复用：只做离线结构判断，不联网。"""
    return analyze_structure(url)["issues"]
