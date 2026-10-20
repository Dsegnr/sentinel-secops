"""密码泄露自查：HIBP Pwned Passwords k-匿名查询。

隐私设计：只发送 SHA-1 前 5 位，其余比对全部在本机完成；报告与案件档中
不保存密码本身（仅保存 SHA-1 前缀用于审计对照）。
"""

from __future__ import annotations

import hashlib

from ..core import netintel
from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport


def triage(target: str, client: HttpClient) -> TriageReport:
    password = target or ""
    prefix = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()[:5]
    rep = TriageReport(kind="breach", target=f"密码自查（SHA-1 前缀 {prefix}…）")
    if not password:
        rep.add("输入", "密码为空", Confidence.UNAVAILABLE, "内置")
        return rep
    if len(password) < 4:
        rep.add("查询", "密码过短（<4 位），任何库都没有查询意义；请直接改一个强密码", Confidence.LIKELY, "内置")

    try:
        count = netintel.pwned_password_count(password, client)
    except Exception as exc:  # noqa: BLE001
        rep.add("查询", f"失败：{str(exc)[:110]}", Confidence.UNAVAILABLE, "HIBP")
        rep.sources.append(SourceResult("HIBP Pwned Passwords", False, error=str(exc)[:110]))
        rep.note("HIBP 不可达时无法自查；可稍后重试。")
        return rep

    rep.sources.append(SourceResult("HIBP Pwned Passwords", True, "k-匿名区间查询"))
    rep.add("命中次数", f"{count} 次", Confidence.CONFIRMED, "HIBP")
    if count == 0:
        rep.add("风险等级", "低（未命中已知泄露库；不等于绝对安全）", Confidence.LIKELY, "内置规则")
    elif count < 10:
        rep.add("风险等级", "中低（出现过少量泄露记录）", Confidence.LIKELY, "内置规则")
    elif count < 1000:
        rep.add("风险等级", "中高（在泄露字典中较常见）", Confidence.LIKELY, "内置规则")
    else:
        rep.add("风险等级", "高（超高频泄露密码，数分钟内可被撞库破解）", Confidence.LIKELY, "内置规则")

    if count > 0:
        rep.add("处置建议", "立即修改该密码（所有使用过它的账户），且不要与其他站点复用；优先开启两步验证（2FA）。", Confidence.CONFIRMED, "内置规则")
    rep.add("自查入口", "邮箱是否出现在泄露事件中，可到 HIBP 官网用邮箱自查（需人工填写）：https://haveibeenpwned.com/", Confidence.LIKELY, "内置规则")
    rep.note("隐私说明：你的密码从未离开本机；只把 SHA-1 的前 5 位发给 HIBP，剩余比对在本机完成（k-匿名）。")
    rep.note("本条目仅用于自查自己的凭据；请勿用于核查他人密码（也无法做到）。")
    return rep
