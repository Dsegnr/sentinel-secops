"""邮件头分析：解析原始邮件头，核验认证链、发现伪造特征、提取可疑链接。

用于钓鱼邮件研判：把邮件「显示原始邮件 / Show original」内容粘贴进来即可。
"""

from __future__ import annotations

import re

from ..core import netintel
from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport
from . import url as url_mod

_ADDR_RE = re.compile(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)


def _parse_headers(raw: str) -> dict:
    """展开折叠行，返回 {header: [values]}。"""
    lines = raw.replace("\r\n", "\n").split("\n")
    fields: dict[str, list[str]] = {}
    current = None
    for line in lines:
        if not line.strip():
            break  # 头与正文分界
        if line[:1] in (" ", "\t") and current:
            fields[current][-1] += " " + line.strip()
            continue
        match = re.match(r"^([A-Za-z-]+):\s*(.*)$", line)
        if match:
            current = match.group(1).lower()
            fields.setdefault(current, []).append(match.group(2).strip())
    return fields


def _first(fields: dict, name: str) -> str:
    values = fields.get(name) or []
    return values[0] if values else ""


def _domain_of(addr_field: str) -> str:
    matches = _ADDR_RE.findall(addr_field or "")
    return matches[0].split("@")[-1].lower() if matches else ""


def _auth_summary(fields: dict) -> str:
    text = " ".join(fields.get("authentication-results", []) + fields.get("arc-authentication-results", []))
    if not text:
        return ""
    parts = []
    for key in ("spf", "dkim", "dmarc"):
        match = re.search(rf"\b{key}\s*=\s*(\w+)", text, re.I)
        if match:
            parts.append(f"{key.upper()}={match.group(1).lower()}")
    return " · ".join(parts)


def triage(raw: str, client: HttpClient) -> TriageReport:
    subject_hint = "邮件头分析"
    rep = TriageReport(kind="email", target=subject_hint)
    if not raw or len(raw.strip()) < 20:
        rep.add("输入", "内容太短，请粘贴完整的原始邮件头", Confidence.UNAVAILABLE, "内置")
        return rep

    fields = _parse_headers(raw)
    from_field = _first(fields, "from")
    return_path = _first(fields, "return-path")
    reply_to = _first(fields, "reply-to")
    subject = _first(fields, "subject")
    message_id = _first(fields, "message-id")
    date = _first(fields, "date")
    received = fields.get("received", [])

    rep.target = f"邮件头·{subject[:50]}" if subject else subject_hint
    if subject:
        rep.add("主题", subject[:150], Confidence.CONFIRMED, "邮件头")
    if from_field:
        rep.add("From", from_field[:150], Confidence.CONFIRMED, "邮件头")
    if return_path:
        rep.add("Return-Path", return_path[:120], Confidence.CONFIRMED, "邮件头")
    if reply_to:
        rep.add("Reply-To", reply_to[:120], Confidence.CONFIRMED, "邮件头")
    if date:
        rep.add("Date", date[:80], Confidence.CONFIRMED, "邮件头")
    if message_id:
        rep.add("Message-ID", message_id[:120], Confidence.UNVERIFIED, "邮件头")
    rep.add("Received 跳数", str(len(received)), Confidence.CONFIRMED, "邮件头")
    if received:
        last_hop = " ".join(received[-1].split())[:160]
        rep.add("最后一跳", last_hop, Confidence.UNVERIFIED, "邮件头")

    auth = _auth_summary(fields)
    if auth:
        rep.add("认证结果（由收件方代写）", auth, Confidence.LIKELY, "邮件头")
        if re.search(r"dmarc=fail", auth, re.I) or re.search(r"spf=fail", auth, re.I):
            rep.add("认证判定", "存在 FAIL 项：该邮件很可能未通过发件域认证，钓鱼风险高", Confidence.LIKELY, "内置规则")
    else:
        rep.add("认证结果（由收件方代写）", "未在邮件头中找到 Authentication-Results（可能被截断）", Confidence.UNAVAILABLE, "邮件头")

    issues: list[str] = []
    from_domain = _domain_of(from_field)
    rp_domain = _domain_of(return_path)
    rt_domain = _domain_of(reply_to)
    if from_domain and rp_domain and from_domain != rp_domain:
        issues.append(f"From 域（{from_domain}）与 Return-Path 域（{rp_domain}）不一致")
    if from_domain and rt_domain and from_domain != rt_domain:
        issues.append(f"Reply-To 指向另一个域（{rt_domain}），回复会被引导走")
    display_email = _ADDR_RE.search(from_field.split("<")[0]) if "<" in from_field else None
    if display_email:
        issues.append("显示名中包含另一个邮箱地址（典型伪装手法）")

    # 发件域邮件安全配置（现状核实，非本封邮件认证）
    if from_domain:
        try:
            records = netintel.resolve_records(from_domain, timeout=4.0, types=("TXT",))
            spf = netintel.txt_of(records, "v=spf1")
            dmarc = netintel.txt_of(
                netintel.resolve_records(f"_dmarc.{from_domain}", timeout=4.0, types=("TXT",)), "v=DMARC1"
            )
            status = []
            status.append("SPF 已配置" if spf else "SPF 未配置（该域可被任意伪造）")
            status.append("DMARC 已配置" if dmarc else "DMARC 未配置")
            rep.add("发件域邮件安全", f"{from_domain}：" + "；".join(status), Confidence.LIKELY, "DNS")
            if not spf or not dmarc:
                issues.append("发件域缺失 SPF/DMARC（伪造成本低）")
        except Exception:  # noqa: BLE001
            pass

    urls = list(dict.fromkeys(_URL_RE.findall(raw)))[:12]
    if urls:
        flagged: list[str] = []
        for link in urls:
            flags = url_mod.offline_flags(link)
            if flags:
                flagged.append(f"{link[:80]}（{'；'.join(flags[:2])}）")
        rep.add("链接数量", str(len(urls)), Confidence.CONFIRMED, "内置解析")
        if flagged:
            issues.append(f"含可疑链接 {len(flagged)} 个")
            rep.add("可疑链接", " ｜ ".join(flagged[:5]), Confidence.LIKELY, "内置规则")

    if issues:
        rep.add("伪造特征", "；".join(f"⚠ {i}" for i in issues), Confidence.LIKELY, "内置规则")
        rep.add("处置建议", "不要点击链接/附件；通过官方渠道二次核实；必要时向收件方管理员报告该邮件。", Confidence.LIKELY, "内置规则")
    else:
        rep.add("伪造特征", "未发现明显伪造特征（仍需结合正文与附件判断）", Confidence.UNVERIFIED, "内置规则")

    rep.sources.append(SourceResult("邮件头解析", True, "离线解析 + DNS 上下文"))
    rep.note("认证结果的权威判定由收件方服务器完成（Authentication-Results 字段），本工具做的是交叉核验与特征提示。")
    return rep
