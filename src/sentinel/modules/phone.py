"""电话号码研判：libphonenumber 离线解析 + 360 号码库（公开归属地/运营商）交叉。

骚扰 / 诈骗电话处置建议内置在报告中；号码标记查询与举报入口见「公开搜索直达」。
"""

from __future__ import annotations

import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder, timezone

from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport

_TYPE_ZH = {
    PhoneNumberType.MOBILE: "移动电话",
    PhoneNumberType.FIXED_LINE: "固定电话",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "固话或手机",
    PhoneNumberType.TOLL_FREE: "免费电话",
    PhoneNumberType.PREMIUM_RATE: "高费率号码",
    PhoneNumberType.VOIP: "VoIP 网络电话",
    PhoneNumberType.PERSONAL_NUMBER: "个人号码",
    PhoneNumberType.PAGER: "寻呼机",
    PhoneNumberType.UAN: "企业接入号",
    PhoneNumberType.VOICEMAIL: "语音信箱",
    PhoneNumberType.UNKNOWN: "未知类型",
}


def triage(target: str, region: str | None = None, client: HttpClient | None = None) -> TriageReport:
    rep = TriageReport(kind="phone", target=target)

    parsed = None
    parse_error = ""
    for reg in ([region] if region else []) + [None, "CN"]:
        try:
            parsed = phonenumbers.parse(target, reg)
            break
        except phonenumbers.NumberParseException as exc:
            parse_error = str(exc)
    if parsed is None:
        rep.add("解析", f"失败：{parse_error}", Confidence.UNAVAILABLE, "libphonenumber")
        rep.note("号码格式无法解析；请检查国家码，或用 --region CN 指定地区。")
        return rep

    e164 = phonenumbers.format_number(parsed, PhoneNumberFormat.E164)
    rep.add("E.164", e164, Confidence.CONFIRMED, "libphonenumber")

    valid = phonenumbers.is_valid_number(parsed)
    rep.add("合法性", "有效号码" if valid else "无效 / 未启用号段", Confidence.CONFIRMED, "libphonenumber")

    region_code = phonenumbers.region_code_for_number(parsed) or "?"
    rep.add("国家/地区", region_code, Confidence.CONFIRMED, "libphonenumber")

    geo = geocoder.description_for_number(parsed, "zh") or geocoder.description_for_number(parsed, "en")
    if geo:
        rep.add("归属地", geo, Confidence.LIKELY, "libphonenumber")

    car = carrier.name_for_number(parsed, "zh") or carrier.name_for_number(parsed, "en")
    if car:
        rep.add("运营商", car, Confidence.LIKELY, "libphonenumber")
    else:
        rep.add("运营商", "公开号段库未收录（常见于虚拟号 / VoIP）", Confidence.UNAVAILABLE, "libphonenumber")

    ntype = phonenumbers.number_type(parsed)
    rep.add("线路类型", _TYPE_ZH.get(ntype, str(ntype)), Confidence.LIKELY, "libphonenumber")

    tzs = timezone.time_zones_for_number(parsed)
    if tzs:
        rep.add("时区", ", ".join(tzs), Confidence.LIKELY, "libphonenumber")

    rep.sources.append(
        SourceResult("libphonenumber(离线)", True, "解析成功" if valid else "号段未验证")
    )

    # 360 号码库（公开、免 key）：仅对中国大陆手机号有意义
    if client is not None:
        region_code = phonenumbers.region_code_for_number(parsed)
        if region_code == "CN":
            findings, source = _src_360(parsed, client)
            for key, value, conf, src in findings:
                rep.add(key, value, conf, src)
            rep.sources.append(source)
        else:
            rep.sources.append(SourceResult("360 号码库", True, "非中国大陆号码，已跳过"))

    rep.note("上限为号段级公开元数据：无法核验实名、机主或实时位置。")
    rep.note("360 号码库为公开号段数据，归属地≠现居地；号码标记可到 360 / 百度号码页查询。")
    rep.note("骚扰/诈骗处置：① 运营商开通防骚扰（移动/联通/电信均有免费服务）② 12321 举报 ③ 涉钱款立即拨 96110 ④ 通话录音/短信截图留档。")
    return rep


def _src_360(parsed, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    digits = phonenumbers.national_significant_number(parsed)
    try:
        data = client.get(
            "https://cx.shouji.360.cn/phonearea.php", params={"number": digits}, timeout=8, retries=0
        ).json()
        if data.get("code") != 0:
            raise ValueError(f"code={data.get('code')}")
        info = data.get("data") or {}
        geo = " / ".join(x for x in (info.get("province"), info.get("city")) if x)
        if geo:
            findings.append(("归属地(360)", geo, Confidence.LIKELY, "360 号码库"))
        if info.get("sp"):
            findings.append(("运营商(360)", str(info["sp"]), Confidence.LIKELY, "360 号码库"))
        if not geo and not info.get("sp"):
            return findings, SourceResult("360 号码库", False, error="公开库无该号段记录")
        return findings, SourceResult("360 号码库", True, "公开归属地接口（免 key）")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("360 号码库", False, error=str(exc)[:120])
