"""邮箱地址研判：格式 / 服务商与一次性邮箱识别 / DNS 与邮件认证（SPF·DMARC·DKIM）
/ Gravatar 公开头像 / 前缀跨平台探活（可选）/ 服务商举报通道。

只用公开数据源（系统 DNS 公开记录、公开头像端点、公开平台主页）。
邮箱的实名与绑定手机仅服务商（网易 / 腾讯 / Google 等）掌握，公开渠道不可得；
确需身份信息时走司法调证。本模块不提供、也不支持任何越权获取。
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import re
from pathlib import Path

from ..core import netintel
from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport

_EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+\-']{1,64}@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$"
)

_GENERIC_CHANNELS = "综合举报（国内）：12321.cn ｜ 12377.cn ｜ cyberpolice.cn；涉诈线索：96110"

# 常见免费邮箱：域 -> (名称, 类别, 举报通道提示)
_PROVIDERS: dict[str, tuple[str, str, str]] = {
    # 国内
    "163.com": ("网易 163 邮箱", "free", "垃圾邮件投诉：abuse@163.com（网易官方信箱）"),
    "126.com": ("网易 126 邮箱", "free", "垃圾邮件投诉：abuse@163.com（网易官方信箱）"),
    "yeah.net": ("网易 yeah.net 邮箱", "free", "垃圾邮件投诉：abuse@163.com（网易官方信箱）"),
    "qq.com": ("QQ 邮箱", "free", "可在 QQ 邮箱内直接「举报」；垃圾邮件可转发 abuse@12321.cn"),
    "foxmail.com": ("Foxmail 邮箱", "free", "可在 QQ 邮箱内直接「举报」；垃圾邮件可转发 abuse@12321.cn"),
    "139.com": ("中国移动 139 邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "189.cn": ("中国电信 189 邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "sina.com": ("新浪邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "sina.cn": ("新浪邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "sohu.com": ("搜狐邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "21cn.com": ("21CN 邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "aliyun.com": ("阿里邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    "tom.com": ("TOM 邮箱", "free", "垃圾邮件可转发 abuse@12321.cn"),
    # 国际
    "gmail.com": ("Gmail", "free", "举报入口：https://support.google.com/mail/answer/8253"),
    "googlemail.com": ("Gmail", "free", "举报入口：https://support.google.com/mail/answer/8253"),
    "outlook.com": ("Outlook.com", "free", "投诉：abuse@outlook.com"),
    "hotmail.com": ("Hotmail", "free", "投诉：abuse@outlook.com"),
    "live.com": ("Microsoft 邮箱", "free", "投诉：abuse@outlook.com"),
    "icloud.com": ("iCloud 邮箱", "free", "投诉：abuse@icloud.com"),
    "me.com": ("iCloud 邮箱", "free", "投诉：abuse@icloud.com"),
    "yahoo.com": ("Yahoo 邮箱", "free", ""),
    "protonmail.com": ("Proton Mail", "free", "投诉：abuse@protonmail.com"),
    "proton.me": ("Proton Mail", "free", "投诉：abuse@protonmail.com"),
    "zoho.com": ("Zoho Mail", "free", ""),
}

# 已知一次性 / 临时邮箱域名（启发式清单，非穷尽）
_DISPOSABLE = {
    "mailinator.com", "guerrillamail.com", "sharklasers.com", "grr.la",
    "10minutemail.com", "10minutemail.net", "temp-mail.org", "tempmail.com", "temp-mail.io",
    "yopmail.com", "maildrop.cc", "getnada.com", "dispostable.com", "trashmail.com",
    "throwawaymail.com", "mail.tm", "mailsac.com", "tempmailo.com", "moakt.com", "mailnesia.com",
    "chacuo.net", "24mail.chacuo.net", "bccto.me", "linshiyouxiang.net", "linshiyou.com",
    "smailpro.com", "mail7.io", "tempr.email", "discard.email",
}

_KIND_LABELS = {
    "free": "个人免费邮箱",
    "disposable": "一次性邮箱（临时邮箱服务）",
    "corporate": "独立域邮箱（机构 / 企业域）",
}

_DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "s1", "dkim", "mail"]


def normalize_email(target: str) -> str:
    text = (target or "").strip().strip("<>").strip().lower()
    if "@" not in text:
        return text
    local, _, domain = text.rpartition("@")
    domain = domain.strip().strip(".")
    try:
        domain = domain.encode("idna").decode("ascii")
    except Exception:  # noqa: BLE001
        pass
    return f"{local}@{domain}"


def is_valid_email(addr: str) -> bool:
    return bool(_EMAIL_RE.match(addr or ""))


def split_email(addr: str) -> tuple[str, str]:
    local, _, domain = (addr or "").rpartition("@")
    return local, domain


def gravatar_digest(email: str) -> str:
    return hashlib.md5((email or "").strip().lower().encode("utf-8")).hexdigest()


def classify_provider(domain: str) -> dict[str, str]:
    domain = (domain or "").lower().strip(".")
    if domain in _DISPOSABLE:
        return {"name": "一次性 / 临时邮箱服务", "kind": "disposable", "channel": _GENERIC_CHANNELS}
    for base in _DISPOSABLE:
        if domain.endswith("." + base):
            return {
                "name": f"一次性 / 临时邮箱服务（{base}）",
                "kind": "disposable",
                "channel": _GENERIC_CHANNELS,
            }
    if domain in _PROVIDERS:
        name, kind, channel = _PROVIDERS[domain]
        return {"name": name, "kind": kind, "channel": channel or _GENERIC_CHANNELS}
    return {
        "name": "独立域邮箱（组织自建 / 企业邮箱）",
        "kind": "corporate",
        "channel": _GENERIC_CHANNELS,
    }


def _guess_mail_provider(hosts: list[str]) -> str:
    joined = " ".join(hosts).lower()
    for hint, name in (
        ("google", "Google Workspace"), ("outlook", "Microsoft 365"), ("qq.com", "腾讯企业邮"),
        ("exmail", "腾讯企业邮"), ("163.com", "网易企业邮"), ("126.com", "网易"),
        ("aliyun", "阿里云邮"), ("feishu", "飞书"), ("zoho", "Zoho"), ("protonmail", "Proton"),
    ):
        if hint in joined:
            return name
    return ""


def _src_dns(domain: str) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        records = netintel.resolve_records(domain, timeout=5.0, types=("A", "MX", "TXT"))
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("DNS 解析", False, error=str(exc)[:120])
    if records.get("_errors", {}).get("A") == "NXDOMAIN":
        findings.append(
            ("域名解析", "NXDOMAIN（域名不存在或已停用——该邮箱地址大概率无效）", Confidence.UNAVAILABLE, "DNS")
        )
        return findings, SourceResult("DNS 解析", True, "系统 DNS（dnspython）")
    a_rows = records.get("A") or []
    if a_rows:
        findings.append(("域名 A 记录", "、".join(a_rows[:4]), Confidence.CONFIRMED, "DNS"))
    rows = [r.strip() for r in (records.get("MX") or [])]
    hosts = []
    for row in rows:
        parts = row.split()
        hosts.append(parts[1] if len(parts) > 1 else "")
    if not hosts:
        findings.append(("MX 记录", "未配置 MX（该域当前无法收信）", Confidence.LIKELY, "DNS"))
    elif all(h in ("", ".") for h in hosts):
        findings.append(("MX 记录", "null MX（域名声明不接收邮件）", Confidence.CONFIRMED, "DNS"))
    else:
        provider = _guess_mail_provider(hosts)
        value = "、".join(h for h in hosts if h)[:160] + (f"（{provider}）" if provider else "")
        findings.append(("MX 记录", value, Confidence.CONFIRMED, "DNS"))
    return findings, SourceResult("DNS 解析", True, "系统 DNS（dnspython）")


def _src_mail_auth(domain: str) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    records = netintel.resolve_records(domain, timeout=5.0, types=("TXT",))
    if records.get("_errors", {}).get("TXT") == "NXDOMAIN":
        findings.append(("SPF", "域名不存在（NXDOMAIN），无需核验", Confidence.UNAVAILABLE, "DNS/TXT"))
        return findings, SourceResult("邮件安全", True, "SPF/DMARC/DKIM 公开记录核验")
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
        judgment = {"reject": "拒收（严格）", "quarantine": "隔离（较好）", "none": "仅监控（可被伪造利用）"}.get(
            pol, "未识别策略"
        )
        findings.append(("DMARC", f"p={pol}｜判定：{judgment}", Confidence.LIKELY, "DNS/TXT"))
    else:
        findings.append(
            ("DMARC", "未配置（建议：v=DMARC1; p=none 起步，再升级到 quarantine/reject）", Confidence.UNAVAILABLE, "DNS/TXT")
        )

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
        findings.append(
            ("DKIM 选择器", "常见选择器未命中（可能用自定义选择器，不代表未配置）", Confidence.UNAVAILABLE, "DNS/TXT")
        )
    return findings, SourceResult("邮件安全", True, "SPF/DMARC/DKIM 公开记录核验")


def _src_gravatar(email: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    digest = gravatar_digest(email)
    url = f"https://www.gravatar.com/avatar/{digest}?d=404&s=40"
    try:
        resp = client.get(url, timeout=5, retries=0)
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("Gravatar 公开头像", False, error=f"探测失败: {str(exc)[:100]}")
    if resp.status_code == 200:
        findings.append(
            ("Gravatar 公开头像", f"存在（公开头像：https://www.gravatar.com/avatar/{digest}）", Confidence.LIKELY, "公开头像端点")
        )
    elif resp.status_code == 404:
        findings.append(("Gravatar 公开头像", "未发现（未注册或未公开）", Confidence.UNAVAILABLE, "公开头像端点"))
    else:
        return findings, SourceResult("Gravatar 公开头像", False, error=f"HTTP {resp.status_code}")
    return findings, SourceResult("Gravatar 公开头像", True, "gravatar.com 公开端点（d=404）")


def _src_platforms(
    local: str,
    client: HttpClient,
    platforms_path: Path,
    only: list[str] | None = None,
) -> tuple[list[tuple], SourceResult]:
    from . import username as user_mod

    findings: list[tuple] = []
    if not user_mod.handle_ok(local):
        findings.append(("跨平台前缀探活", "前缀含平台探活不支持的特殊字符，已跳过", Confidence.UNAVAILABLE, "内置"))
        return findings, SourceResult("跨平台探活", False, error="前缀格式不适用")
    rep = user_mod.triage(local, client, platforms_path, only=only)
    values = {f.key: f.value for f in rep.findings}
    stats = values.get("探活统计", "")
    hits = values.get("命中列表", "")
    if stats:
        value = stats + (f"；命中：{hits}" if hits else "")
        findings.append(("跨平台前缀探活", value, Confidence.LIKELY, "公开页面探活·内置"))
    else:
        findings.append(("跨平台前缀探活", "未取得统计（详见独立探活报告）", Confidence.UNAVAILABLE, "公开页面探活·内置"))
    return findings, SourceResult("跨平台探活", True, f"username 引擎（{len(rep.sources)} 数据源）")


def _assess(rep: TriageReport) -> None:
    values = {f.key: f.value for f in rep.findings}
    provider = values.get("服务商", "")
    kind = values.get("邮箱性质", "")
    mx = values.get("MX 记录", "")
    spf = values.get("SPF", "")
    grav = values.get("Gravatar 公开头像", "")
    plat = values.get("跨平台前缀探活", "")

    not_receiving = ("未配置" in mx) or ("null MX" in mx)
    bits = [f"{provider}｜{kind}"] if (provider or kind) else []
    if mx:
        bits.append("当前不接收邮件" if not_receiving else "可收信")
    rep.add("邮箱画像", "；".join(bits) or "-", Confidence.LIKELY, "综合")

    advice: list[str] = []
    if "一次性" in kind:
        advice.append("一次性邮箱：批量注册 / 薅羊毛 / 规避风控高发，来源可信度低")
    if not_receiving:
        advice.append("该域当前不接收邮件（MX 缺失 / null MX），地址大概率无效或已停用")
    if spf.startswith("未配置") and "独立域" in kind:
        advice.append("该域未配置 SPF，可被伪造发信——警惕冒充该域钓鱼")
    if grav.startswith("存在"):
        advice.append("存在 Gravatar 公开头像：可作公开核验线索（同名 ≠ 同一人）")
    if "命中：" in plat:
        advice.append("前缀存在跨平台命中：须人工交叉核验（同名 ≠ 同一人）")
    if advice:
        rep.add("风险与建议", "；".join(advice), Confidence.LIKELY, "综合")


def triage(
    target: str,
    client: HttpClient,
    platforms_path: Path | None = None,
    only: list[str] | None = None,
    skip_gravatar: bool = False,
) -> TriageReport:
    addr = normalize_email(target)
    rep = TriageReport(kind="mailbox", target=addr)
    if not is_valid_email(addr):
        rep.add("格式校验", "不是合法的邮箱地址格式（示例：name@example.com）", Confidence.UNAVAILABLE, "内置")
        return rep
    local, domain = split_email(addr)
    provider = classify_provider(domain)
    rep.add("格式校验", "合法", Confidence.CONFIRMED, "内置")
    rep.add("本地部分（前缀）", local, Confidence.CONFIRMED, "内置")
    rep.add("服务商", provider["name"], Confidence.LIKELY, "内置")
    rep.add("邮箱性质", _KIND_LABELS.get(provider["kind"], provider["kind"]), Confidence.LIKELY, "内置")
    rep.add("举报 / 申诉通道", provider["channel"], Confidence.LIKELY, "公开信息")

    jobs = {
        "DNS 解析": lambda: _src_dns(domain),
        "邮件安全": lambda: _src_mail_auth(domain),
    }
    if not skip_gravatar:
        jobs["Gravatar 公开头像"] = lambda: _src_gravatar(addr, client)
    if platforms_path is not None:
        jobs["跨平台探活"] = lambda: _src_platforms(local, client, platforms_path, only=only)

    results: dict[str, tuple[list[tuple], SourceResult]] = {}
    with cf.ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        futures = {pool.submit(fn): name for name, fn in jobs.items()}
        for fut in cf.as_completed(futures):
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[name] = ([], SourceResult(name, False, error=str(exc)[:120]))

    order = ["DNS 解析", "邮件安全"]
    if not skip_gravatar:
        order.append("Gravatar 公开头像")
    if platforms_path is not None:
        order.append("跨平台探活")
    for name in order:
        findings, source = results.get(name, ([], SourceResult(name, False, error="未执行")))
        for key, value, conf, src in findings:
            rep.add(key, value, conf, src)
        rep.sources.append(source)

    grav_src = next((s for s in rep.sources if s.source == "Gravatar 公开头像"), None)
    if grav_src is not None and not grav_src.ok:
        rep.note("注：Gravatar 探测源在当前网络不可达（已如实标注 FAIL）——该项为「无法判定」，不代表未注册。")
    if skip_gravatar:
        rep.note("批量模式：已跳过 Gravatar 公开头像探测（控制批量耗时）；单条研判默认包含该项。")

    _assess(rep)
    rep.note("邮箱的实名与绑定手机仅服务商掌握，公开渠道不可得；确需身份信息时走司法调证（报案 / 诉讼）。")
    rep.note("一次性邮箱清单与跨平台探活均为启发式：判定分级 存在 / 未发现 / 无法判定（无法判定 ≠ 不存在）。")
    return rep
