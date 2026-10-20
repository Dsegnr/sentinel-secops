"""域名体检：注册信息 / DNS / 邮件安全（SPF·DMARC·DKIM）/ 子域 / TLS / 安全响应头 / urlscan。

用于防守场景：检查自己的域名是否配置正确（尤其邮件反伪造三件套），
并给出可执行的整改建议；所有数据来自公开源，只读查询。
"""

from __future__ import annotations

import concurrent.futures as cf
import re

from ..core import netintel
from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport

_DKIM_SELECTORS = [
    "default", "google", "selector1", "selector2", "k1", "s1",
    "dkim", "mail", "smtp", "zoho", "mandrill", "sendgrid",
]

_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

_SOURCE_ORDER = ("注册信息", "DNS 解析", "邮件安全", "子域发现", "TLS 证书", "安全响应头", "urlscan 记录")

_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def normalize_domain(target: str) -> str:
    text = (target or "").strip().lower()
    text = re.sub(r"^[a-z]+://", "", text)
    text = text.split("/")[0].split("?")[0].split("#")[0]
    text = text.split("@")[-1]
    text = text.split(":")[0]
    text = text.strip(".")
    try:
        text = text.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        pass
    return text


def triage(target: str, client: HttpClient) -> TriageReport:
    domain = normalize_domain(target)
    rep = TriageReport(kind="domain", target=domain)
    if not _DOMAIN_RE.match(domain):
        rep.add("解析", "不是合法的域名格式", Confidence.UNAVAILABLE, "内置")
        return rep

    jobs = {
        "注册信息": lambda: _src_whois(domain, client),
        "DNS 解析": lambda: _src_dns(domain),
        "邮件安全": lambda: _src_mail_auth(domain),
        "子域发现": lambda: _src_subdomains(domain, client),
        "TLS 证书": lambda: _src_tls(domain),
        "安全响应头": lambda: _src_headers(domain, client),
        "urlscan 记录": lambda: _src_urlscan(domain, client),
    }
    results: dict[str, tuple[list[tuple], SourceResult]] = {}
    with cf.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {pool.submit(fn): name for name, fn in jobs.items()}
        for fut in cf.as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[name] = ([], SourceResult(name, False, error=str(exc)[:120]))

    for name in _SOURCE_ORDER:
        findings, source = results.get(name, ([], SourceResult(name, False, error="未执行")))
        for key, value, conf, src in findings:
            rep.add(key, value, conf, src)
        rep.sources.append(source)

    _assess(rep)
    rep.note("域名体检用于防守自查：邮件安全（SPF/DMARC/DKIM）缺失会导致域名可被伪造发信。")
    rep.note("子域来自证书透明度等公开源，可能不完整；面向公众的资产建议同时做主动梳理。")
    return rep


# ---------------- 各数据源 ----------------

def _src_whois(domain: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    info: dict = {}
    label = ""
    try:
        rdap = netintel.rdap_domain(domain, client)
        if rdap:
            info, label = rdap, f"RDAP · {rdap['server']}"
    except Exception:  # noqa: BLE001
        pass
    if not info:
        try:
            who = netintel.whois_lookup(domain)
            info = who
            label = f"WHOIS · {who['server']}"
        except Exception as exc:  # noqa: BLE001
            return findings, SourceResult("注册信息", False, error=f"WHOIS/RDAP 均失败: {str(exc)[:100]}")

    if info.get("registrar"):
        findings.append(("注册商", info["registrar"], Confidence.LIKELY, label))
    if info.get("created"):
        age = netintel.fmt_age(info["created"])
        value = f"{info['created']}" + (f"（约 {age}）" if age else "")
        findings.append(("注册时间", value, Confidence.LIKELY, label))
    if info.get("expires"):
        findings.append(("到期时间", info["expires"], Confidence.LIKELY, label))
    if info.get("updated"):
        findings.append(("更新时间", info["updated"], Confidence.UNVERIFIED, label))
    if info.get("statuses"):
        findings.append(("域名状态", "、".join(info["statuses"][:5]), Confidence.LIKELY, label))
    if info.get("nameservers"):
        findings.append(("注册局 NS", "、".join(info["nameservers"][:5]), Confidence.LIKELY, label))
    if info.get("abuse_email"):
        findings.append(("Abuse 联系", info["abuse_email"], Confidence.LIKELY, label))
    return findings, SourceResult("注册信息", True, label)


def _src_dns(domain: str) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    records = netintel.resolve_records(domain)
    if records.get("_errors", {}).get("A") == "NXDOMAIN":
        return findings, SourceResult("DNS 解析", False, error="NXDOMAIN（域名不存在或已停用）")
    for rtype, label in (("A", "A 记录"), ("AAAA", "AAAA 记录"), ("CNAME", "CNAME"), ("NS", "权威 NS")):
        rows = records.get(rtype) or []
        if rows:
            findings.append((label, "、".join(rows[:6]) + ("…" if len(rows) > 6 else ""), Confidence.CONFIRMED, "DNS"))
    mx = records.get("MX") or []
    if mx:
        providers = _guess_mail_provider(mx)
        value = "、".join(mx[:4]) + (f"（{providers}）" if providers else "")
        findings.append(("MX 记录", value, Confidence.CONFIRMED, "DNS"))
    txt_count = len(records.get("TXT") or [])
    if txt_count:
        findings.append(("TXT 记录数", str(txt_count), Confidence.CONFIRMED, "DNS"))
    return findings, SourceResult("DNS 解析", True, "系统 DNS（dnspython）")


def _guess_mail_provider(mx: list[str]) -> str:
    joined = " ".join(mx).lower()
    for hint, name in (
        ("google", "Google Workspace"), ("outlook", "Microsoft 365"), ("qq.com", "腾讯企业邮"),
        ("163.com", "网易企业邮"), ("aliyun", "阿里云邮"), ("feishu", "飞书"), ("zoho", "Zoho"),
    ):
        if hint in joined:
            return name
    return ""


def _src_mail_auth(domain: str) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    records = netintel.resolve_records(domain, timeout=5.0, types=("TXT",))
    spf = netintel.txt_of(records, "v=spf1")
    if spf:
        record = spf[0]
        all_match = re.search(r"([-~+?])all", record, re.I)
        judgment = {
            "-": "硬失败（-all，配置严格）",
            "~": "软失败（~all，建议升级为 -all）",
            "+": "全部放行（+all，形同虚设）",
            "?": "中性（?all，形同虚设）",
        }.get(all_match.group(1) if all_match else "", "未写 all 机制")
        findings.append(("SPF", f"{record[:110]}｜判定：{judgment}", Confidence.LIKELY, "DNS/TXT"))
    else:
        findings.append(("SPF", "未配置（任何人可伪造该域发信）", Confidence.UNAVAILABLE, "DNS/TXT"))

    dmarc_rec = netintel.resolve_records(f"_dmarc.{domain}", timeout=5.0, types=("TXT",))
    dmarc = netintel.txt_of(dmarc_rec, "v=DMARC1")
    if dmarc:
        policy = re.search(r"\bp\s*=\s*(none|quarantine|reject)", dmarc[0], re.I)
        pol = policy.group(1).lower() if policy else "?"
        judgment = {"reject": "拒收（严格）", "quarantine": "隔离（较好）", "none": "仅监控（可被伪造利用）"}.get(pol, "未识别策略")
        findings.append(("DMARC", f"p={pol}｜判定：{judgment}", Confidence.LIKELY, "DNS/TXT"))
    else:
        findings.append(("DMARC", "未配置（建议：v=DMARC1; p=none 起步，再升级到 quarantine/reject）", Confidence.UNAVAILABLE, "DNS/TXT"))

    def _selector_hit(selector: str) -> str | None:
        rec = netintel.resolve_records(f"{selector}._domainkey.{domain}", timeout=3.5, types=("TXT",))
        for row in netintel.txt_of(rec, "v=DKIM1"):
            if re.search(r"p\s*=\s*[A-Za-z0-9+/]{8,}", row):
                return selector
        return None

    hits: list[str] = []
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        for result in pool.map(_selector_hit, _DKIM_SELECTORS):
            if result:
                hits.append(result)
    if hits:
        findings.append(("DKIM 选择器", "、".join(hits), Confidence.LIKELY, "DNS/TXT"))
    else:
        findings.append(("DKIM 选择器", "常见选择器未命中（可能用自定义选择器，不代表未配置）", Confidence.UNAVAILABLE, "DNS/TXT"))
    return findings, SourceResult("邮件安全", True, "SPF/DMARC/DKIM 公开记录核验")


def _src_subdomains(domain: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    collected: set[str] = set()
    details: list[str] = []
    ok_any = False
    for name, fn in (("CertSpotter", netintel.certspotter_subdomains), ("HackerTarget", netintel.hackertarget_hosts)):
        try:
            names = fn(domain, client)
            collected.update(names)
            details.append(f"{name} {len(names)} 条")
            ok_any = True
        except Exception as exc:  # noqa: BLE001
            details.append(f"{name} 失败: {str(exc)[:60]}")
    if collected:
        sample = sorted(collected)[:15]
        findings.append(("子域数量", str(len(collected)), Confidence.LIKELY, "证书透明度"))
        findings.append(("子域样例", "、".join(sample) + ("…" if len(collected) > 15 else ""), Confidence.LIKELY, "证书透明度"))
    return findings, SourceResult("子域发现", ok_any, "；".join(details))


def _src_tls(domain: str) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        info = netintel.tls_info(domain)
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("TLS 证书", False, error=f"连接失败: {str(exc)[:100]}")
    if info.get("issuer"):
        findings.append(("证书颁发者", info["issuer"], Confidence.CONFIRMED, "TLS 直连"))
    if info.get("not_after"):
        days = info.get("days_left")
        suffix = f"（剩余 {days} 天）" if days is not None else ""
        findings.append(("证书到期", f"{info['not_after']}{suffix}", Confidence.CONFIRMED, "TLS 直连"))
    if info.get("san_count") is not None:
        findings.append(("证书 SAN 数", str(info["san_count"]), Confidence.CONFIRMED, "TLS 直连"))
    if info.get("tls_version"):
        findings.append(("TLS 版本", str(info["tls_version"]), Confidence.CONFIRMED, "TLS 直连"))
    return findings, SourceResult("TLS 证书", True, "直连 :443 读取证书")


def _src_headers(domain: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    resp = None
    last_error = ""
    for scheme in ("https", "http"):
        try:
            resp = client.get(f"{scheme}://{domain}/", timeout=8, retries=0)
            break
        except Exception as exc:  # noqa: BLE001
            last_error = str(exc)
            resp = None
    if resp is None:
        return findings, SourceResult("安全响应头", False, error=f"HTTP/HTTPS 均不可达: {last_error[:90]}")
    final_url = str(resp.url)
    findings.append(("HTTP 状态", f"{resp.status_code} → {final_url[:90]}", Confidence.CONFIRMED, "HTTPS 探测"))
    if final_url.startswith("http://"):
        findings.append(("HTTPS 强制", "未强制 HTTPS（可被中间人劫持）", Confidence.LIKELY, "HTTPS 探测"))
    present, missing = [], []
    for header, label in _SECURITY_HEADERS.items():
        (present if resp.headers.get(header) else missing).append(label)
    findings.append((
        "安全响应头",
        f"已配置 {len(present)}/{len(_SECURITY_HEADERS)}" + (f"；缺失：{'、'.join(missing)}" if missing else "；齐全"),
        Confidence.CONFIRMED,
        "HTTPS 探测",
    ))
    if resp.headers.get("server"):
        findings.append(("Server 头", str(resp.headers["server"])[:80], Confidence.UNVERIFIED, "HTTPS 探测"))
    return findings, SourceResult("安全响应头", True, f"HTTP {resp.status_code}")


def _src_urlscan(domain: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        resp = client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 5},
            timeout=8,
            retries=0,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        data = resp.json()
        total = data.get("total", 0)
        sample = "、".join((r.get("task") or {}).get("url", "")[:60] for r in (data.get("results") or [])[:3])
        findings.append(("urlscan 公开记录", f"{total} 条" + (f"；最近：{sample}" if sample else ""), Confidence.LIKELY, "urlscan.io"))
        return findings, SourceResult("urlscan 记录", True, "公开扫描检索")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("urlscan 记录", False, error=str(exc)[:100])


# ---------------- 体检评估 ----------------

def _assess(rep: TriageReport) -> None:
    values = {f.key: f.value for f in rep.findings}
    issues: list[str] = []
    warns: list[str] = []

    if "未配置" in values.get("SPF", ""):
        issues.append("SPF 未配置")
    if "未配置" in values.get("DMARC", ""):
        issues.append("DMARC 未配置")
    elif "p=none" in values.get("DMARC", ""):
        warns.append("DMARC 仅为监控模式（p=none）")
    miss_match = re.search(r"缺失：(.+)$", values.get("安全响应头", ""))
    if miss_match:
        missing = [x.strip() for x in miss_match.group(1).split("、")]
        key_missing = [x for x in missing if x in ("HSTS", "CSP")]
        if key_missing:
            warns.append("缺少 " + "、".join(key_missing))
    days_match = re.search(r"剩余 (\d+) 天", values.get("证书到期", ""))
    if days_match and int(days_match.group(1)) <= 14:
        issues.append(f"证书 {days_match.group(1)} 天内到期")
    age_match = re.search(r"约 (\d+) 天", values.get("注册时间", ""))
    if age_match and int(age_match.group(1)) < 180:
        warns.append("域名注册时间不足半年")

    flagged = issues + warns
    if not flagged:
        rating = "A（未发现明显风险项）"
    elif len(flagged) <= 2:
        rating = "B（少数项目待完善）"
    elif len(flagged) <= 4:
        rating = "C（存在明确风险项，建议整改）"
    else:
        rating = "D（风险项较多，优先处理）"
    rep.add("体检评级", rating, Confidence.LIKELY, "内置规则")
    if flagged:
        rep.add("问题清单", "；".join(flagged), Confidence.LIKELY, "内置规则")
