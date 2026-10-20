"""IP 研判：地理 / ASN / 网络性质 / 反查 / RDAP / 开放端口 / 威胁情报 / 封堵清单命中。

数据源全部实测可用（2026-10-11，见 checks/probe_public_sources.py）：
ipwho.is、ip-api.com、Shodan InternetDB、ISC DShield、blocklist.de、RIPEstat、
PTR、RDAP（ARIN/APNIC）、urlscan 公开检索、本地封堵清单（FireHOL/Spamhaus）。
只查询公网地址。
"""

from __future__ import annotations

import concurrent.futures as cf
import ipaddress
import re
import socket
import threading

from ..core.blocklist import BlocklistStore
from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport

# 报告展示顺序（并行执行，顺序合并）
_SOURCE_ORDER = (
    "ipwho.is", "ip-api.com", "InternetDB", "DShield", "blocklist.de",
    "RIPEstat", "PTR", "RDAP", "urlscan", "封堵清单",
)

_RDAP_ENDPOINTS = (
    "https://rdap.apnic.net/ip/{ip}",
    "https://rdap.org/ip/{ip}",
)

_RDAP_BUDGET_S = 8.0

# 快速源整体预算：超预算的源标记"已跳过"，避免个别慢源拖垮整个研判
_FAST_BUDGET_S = 12.0


def triage(target: str, client: HttpClient, blocklist: BlocklistStore | None = None) -> TriageReport:
    rep = TriageReport(kind="ip", target=target)
    try:
        ip = ipaddress.ip_address(target.strip())
    except ValueError:
        rep.add("解析", "不是合法的 IP 地址", Confidence.UNAVAILABLE, "内置")
        return rep
    if not ip.is_global:
        rep.add("目标", f"{ip} 属于私有 / 保留网段", Confidence.CONFIRMED, "内置")
        rep.note("私有 / 保留地址不会出网查询（也没有公开情报意义）。")
        return rep

    fast_jobs = {
        "ipwho.is": lambda: _src_ipwhois(target, client),
        "ip-api.com": lambda: _src_ipapi(target, client),
        "InternetDB": lambda: _src_internetdb(target, client),
        "DShield": lambda: _src_dshield(target, client),
        "blocklist.de": lambda: _src_blocklistde(target, client),
        "RIPEstat": lambda: _src_ripestat(target, client),
        "PTR": lambda: _src_ptr(target),
        "urlscan": lambda: _src_urlscan(target, client),
    }
    if blocklist is not None:
        fast_jobs["封堵清单"] = lambda: _src_local_blocklist(target, blocklist)

    results: dict[str, tuple[list[tuple], SourceResult]] = {}

    rdap_box: dict = {}
    rdap_thread = threading.Thread(
        target=lambda: rdap_box.setdefault("r", _src_rdap(target, client)), daemon=True
    )
    rdap_thread.start()

    executor = cf.ThreadPoolExecutor(max_workers=len(fast_jobs))
    try:
        futures = {executor.submit(fn): name for name, fn in fast_jobs.items()}
        done, pending = cf.wait(futures, timeout=_FAST_BUDGET_S)
        for fut in done:
            name = futures[fut]
            try:
                results[name] = fut.result()
            except Exception as exc:  # noqa: BLE001
                results[name] = ([], SourceResult(name, False, error=str(exc)[:120]))
        for fut in pending:
            name = futures[fut]
            results[name] = ([], SourceResult(name, False, error=f"超时（>{_FAST_BUDGET_S:.0f}s 预算，已跳过）"))
    finally:
        executor.shutdown(wait=False)

    rdap_thread.join(timeout=_RDAP_BUDGET_S)
    if "r" in rdap_box:
        results["RDAP"] = rdap_box["r"]
    else:
        results["RDAP"] = ([], SourceResult("RDAP", False, error=f"超时（>{_RDAP_BUDGET_S:.0f}s，已跳过）"))

    threat_hits: list[str] = []
    for name in _SOURCE_ORDER:
        findings, source = results.get(name, ([], SourceResult(name, False, error="未执行")))
        for key, value, conf, src in findings:
            rep.add(key, value, conf, src)
            if _risk_signal(key, value):
                threat_hits.append(key)
        rep.sources.append(source)

    if threat_hits:
        rep.add(
            "威胁情报汇总",
            f"命中 {len(threat_hits)} 类情报项（{'、'.join(threat_hits[:5])}）；建议阻断该地址并核查内网是否有连接记录。",
            Confidence.LIKELY,
            "内置规则",
        )
    rep.note("IP 定位上限为城市 / 机房级；对方使用代理或 VPN 时，地理信息只代表出口节点。")
    rep.note("开放端口与 CVE 为 Shodan 历史观测值，可能过期；不要据此直接对外扫描。")
    rep.note("判定为恶意来源时，可结合 abuse 联系生成举报（留证：截图 + 时间 + 完整报文）。")
    return rep


# ---------------- 各数据源 ----------------

def _src_ipwhois(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        data = client.get(f"https://ipwho.is/{target}", timeout=8, retries=0).json()
        if not data.get("success", False):
            raise ValueError(data.get("message", "查询失败"))
        country = f"{data.get('country', '?')} ({data.get('country_code', '?')})"
        findings.append(("国家", country, Confidence.LIKELY, "ipwho.is"))
        city = " / ".join(x for x in (data.get("city"), data.get("region")) if x)
        if city:
            findings.append(("城市(机房级)", city, Confidence.UNVERIFIED, "ipwho.is"))
        conn = data.get("connection") or {}
        isp = conn.get("isp") or conn.get("org")
        if isp:
            findings.append(("ISP/机构", isp, Confidence.LIKELY, "ipwho.is"))
        if conn.get("asn"):
            findings.append(("ASN", f"AS{conn['asn']}", Confidence.LIKELY, "ipwho.is"))
        tzid = (data.get("timezone") or {}).get("id")
        if tzid:
            findings.append(("时区", tzid, Confidence.LIKELY, "ipwho.is"))
        return findings, SourceResult("ipwho.is", True, "HTTPS 主源")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("ipwho.is", False, error=str(exc)[:120])


def _src_ipapi(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        data = client.get(f"http://ip-api.com/json/{target}", params={"lang": "zh-CN"}).json()
        if data.get("status") != "success":
            raise ValueError(data.get("message", "查询失败"))
        flags = []
        if data.get("proxy"):
            flags.append("代理 / VPN")
        if data.get("hosting"):
            flags.append("数据中心 / 托管")
        if flags:
            findings.append(("网络性质", "、".join(flags), Confidence.LIKELY, "ip-api.com"))
        else:
            findings.append(("网络性质", "未标记为代理 / 托管", Confidence.UNVERIFIED, "ip-api.com"))
        if data.get("as"):
            findings.append(("AS", str(data["as"]), Confidence.LIKELY, "ip-api.com"))
        if data.get("isp"):
            findings.append(("ISP(交叉)", str(data["isp"]), Confidence.LIKELY, "ip-api.com"))
        return findings, SourceResult("ip-api.com", True, "HTTP 免费源（交叉验证）")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("ip-api.com", False, error=str(exc)[:120])


def _src_internetdb(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    """Shodan InternetDB：开放端口 / 主机名 / 已知 CVE / 标签（免 key）。"""
    findings: list[tuple] = []
    try:
        resp = client.get(f"https://internetdb.shodan.io/{target}", timeout=8, retries=0)
        if resp.status_code == 404:
            return findings, SourceResult("InternetDB", True, "无历史观测数据（正常）")
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        data = resp.json()
        ports = data.get("ports") or []
        if ports:
            findings.append(("开放端口(历史观测)", "、".join(str(p) for p in sorted(ports)[:20]), Confidence.LIKELY, "InternetDB"))
        hostnames = data.get("hostnames") or []
        if hostnames:
            findings.append(("主机名线索", "、".join(hostnames[:5]), Confidence.UNVERIFIED, "InternetDB"))
        vulns = data.get("vulns") or []
        if vulns:
            findings.append(("已知 CVE", "、".join(sorted(vulns)[:8]) + ("…" if len(vulns) > 8 else ""), Confidence.UNVERIFIED, "InternetDB"))
        tags = data.get("tags") or []
        if tags:
            findings.append(("Shodan 标签", "、".join(str(t) for t in tags[:8]), Confidence.UNVERIFIED, "InternetDB"))
        return findings, SourceResult("InternetDB", True, "公开历史观测（免 key）")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("InternetDB", False, error=str(exc)[:120])


def _src_dshield(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        data = client.get(f"https://isc.sans.edu/api/ip/{target}", params={"json": ""}, timeout=8, retries=0).json()
        info = data.get("ip") or {}
        attacks = info.get("attacks")
        count = info.get("count")
        if attacks or count:
            findings.append(("DShield 攻击记录", f"attacks={attacks or 0} / count={count or 0}", Confidence.LIKELY, "ISC DShield"))
        if info.get("maxdate"):
            findings.append(("最近攻击时间", str(info["maxdate"]), Confidence.LIKELY, "ISC DShield"))
        if info.get("comment"):
            findings.append(("DShield 备注", str(info["comment"])[:120], Confidence.UNVERIFIED, "ISC DShield"))
        if info.get("asabusecontact"):
            findings.append(("Abuse 联系(SANS)", str(info["asabusecontact"])[:120], Confidence.LIKELY, "ISC DShield"))
        return findings, SourceResult("DShield", True, "SANS 攻击观测库")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("DShield", False, error=str(exc)[:120])


def _src_blocklistde(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        text = client.get(f"https://api.blocklist.de/api.php", params={"ip": target}, timeout=12, retries=0).text
        attacks = _int_after(text, "attacks")
        reports = _int_after(text, "reports")
        if attacks is None and reports is None:
            raise ValueError(f"响应异常: {text[:60]}")
        findings.append(("blocklist.de 举报/攻击", f"reports={reports or 0} / attacks={attacks or 0}", Confidence.LIKELY, "blocklist.de"))
        return findings, SourceResult("blocklist.de", True, "公益攻击举报库")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("blocklist.de", False, error=str(exc)[:120])


def _int_after(text: str, key: str) -> int | None:
    match = re.search(rf"{key}\s*:\s*(\d+)", text)
    return int(match.group(1)) if match else None


def _risk_signal(key: str, value: str) -> bool:
    """只有真实的攻击/恶意信号才算威胁命中；公开扫描记录、0 举报不算。"""
    if key == "已知 CVE":
        return True
    if key == "DShield 攻击记录":
        match = re.search(r"attacks=(\d+) / count=(\d+)", value)
        return bool(match and (int(match.group(1)) > 0 or int(match.group(2)) > 0))
    if key == "blocklist.de 举报/攻击":
        match = re.search(r"reports=(\d+) / attacks=(\d+)", value)
        return bool(match and (int(match.group(1)) > 0 or int(match.group(2)) > 0))
    if key == "封堵清单命中":
        return "未命中" not in value
    return False


def _src_ripestat(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        data = client.get(
            "https://stat.ripe.net/data/network-info/data.json",
            params={"resource": target},
            timeout=8,
            retries=0,
        ).json()
        info = data.get("data") or {}
        asns = info.get("asns") or []
        if asns:
            findings.append(("ASN(路由)", "、".join(f"AS{a}" for a in asns), Confidence.LIKELY, "RIPEstat"))
        if info.get("prefix"):
            findings.append(("BGP 前缀", str(info["prefix"]), Confidence.LIKELY, "RIPEstat"))
        return findings, SourceResult("RIPEstat", True, "RIPE 路由视图")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("RIPEstat", False, error=str(exc)[:120])


def _src_ptr(target: str) -> tuple[list[tuple], SourceResult]:
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
        return [("反向解析", hostname, Confidence.LIKELY, "PTR")], SourceResult("PTR", True, "解析成功")
    except Exception as exc:  # noqa: BLE001
        return [], SourceResult("PTR", False, error=str(exc)[:120])


def _src_urlscan(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        resp = client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"ip:{target}", "size": 5},
            timeout=8,
            retries=0,
        )
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        data = resp.json()
        total = data.get("total", 0)
        sample = "、".join((r.get("task") or {}).get("url", "")[:60] for r in (data.get("results") or [])[:2])
        if total:
            findings.append(("urlscan 命中", f"{total} 条公开扫描记录" + (f"；例如 {sample}" if sample else ""), Confidence.LIKELY, "urlscan.io"))
        return findings, SourceResult("urlscan", True, "公开扫描检索")
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("urlscan", False, error=str(exc)[:120])


def _src_local_blocklist(target: str, store: BlocklistStore) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    try:
        hits = store.check_ip(target)
    except Exception as exc:  # noqa: BLE001
        return findings, SourceResult("封堵清单", False, error=str(exc)[:120])
    if not store.load_ranges():
        return findings, SourceResult("封堵清单", False, error="本地清单为空（到工作台「封堵清单」页更新）")
    if hits:
        summary = "；".join(f"{h['source']} {h['cidr']}" for h in hits)
        findings.append(("封堵清单命中", summary, Confidence.CONFIRMED, "本地清单"))
    else:
        findings.append(("封堵清单命中", "未命中 FireHOL/Spamhaus 清单", Confidence.LIKELY, "本地清单"))
    return findings, SourceResult("封堵清单", True, f"覆盖 {len(store.load_ranges())} 条网段")


def _src_rdap(target: str, client: HttpClient) -> tuple[list[tuple], SourceResult]:
    findings: list[tuple] = []
    errors: list[str] = []
    for template in _RDAP_ENDPOINTS:
        url = template.format(ip=target)
        host = url.split("/")[2]
        try:
            resp = client.get(url, allow_redirects=True, timeout=4, retries=0)
            if resp.status_code != 200:
                errors.append(f"{host}: HTTP {resp.status_code}")
                continue
            data = resp.json()
            name = data.get("name") or data.get("handle")
            if name:
                findings.append(("注册网络", str(name), Confidence.LIKELY, "RDAP"))
            abuse = set()
            for ent in data.get("entities") or []:
                if "abuse" not in (ent.get("roles") or []):
                    continue
                for item in (ent.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "email" and len(item) > 3:
                        abuse.add(str(item[3]))
            if abuse:
                findings.append(("Abuse 联系", ", ".join(sorted(abuse)), Confidence.LIKELY, "RDAP"))
            return findings, SourceResult("RDAP", True, f"注册信息（{host}）")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{host}: {str(exc)[:60]}")
    return findings, SourceResult("RDAP", False, error="；".join(errors)[:160])
