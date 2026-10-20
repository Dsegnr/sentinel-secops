"""网络情报底座：DNS / WHOIS / RDAP / TLS / HIBP / 证书透明度。

全部为只读公开源，均已在本机实测可用（见 checks/probe_public_sources.py）：
- 系统 DNS（dnspython，走本机 nameserver，绕开被阻断的 DoH）
- WHOIS over TCP/43（.com / .cn 直连实测可用；其余走 IANA 指引）
- RDAP（Verisign .com/.net、PIR .org 实测可用）
- TLS 证书直连探测
- HIBP Pwned Passwords（k-匿名，只发 SHA-1 前 5 位）
- CertSpotter / HackerTarget 证书与主机发现
"""

from __future__ import annotations

import hashlib
import re
import socket
import ssl
from datetime import datetime, timezone

import dns.resolver

from .http import HttpClient

# ---------------- DNS ----------------

DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME")

# 常见二级后缀（用于从子域推导注册域）
_SECOND_LEVEL = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "co.uk", "org.uk",
    "com.hk", "com.tw", "com.au", "com.sg", "co.jp", "com.br",
}


def registrable_domain(domain: str) -> str:
    """取注册域：a.b.example.com -> example.com；支持 co.uk / com.cn 这类二级后缀。"""
    parts = [p for p in domain.strip().strip(".").lower().split(".") if p]
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def resolve_records(domain: str, timeout: float = 5.0, types: tuple[str, ...] = DNS_TYPES) -> dict:
    """解析常见记录类型；单类型失败不影响其他类型。"""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = timeout
    resolver.timeout = min(timeout, 2.5)
    out: dict = {"domain": domain}
    errors: dict[str, str] = {}
    for rtype in types:
        try:
            answer = resolver.resolve(domain, rtype, raise_on_no_answer=False)
            rows: list[str] = []
            if answer.rrset is not None:
                for rdata in answer:
                    if rtype == "MX":
                        rows.append(f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}")
                    elif rtype == "TXT":
                        rows.append(str(rdata).strip('"'))
                    else:
                        rows.append(rdata.to_text().rstrip("."))
            out[rtype] = rows
        except dns.resolver.NXDOMAIN:
            errors[rtype] = "NXDOMAIN"
            out[rtype] = []
        except Exception as exc:  # noqa: BLE001
            errors[rtype] = type(exc).__name__
            out[rtype] = []
    out["_errors"] = errors
    return out


def txt_of(records: dict, prefix: str) -> list[str]:
    """从解析结果里挑出以 prefix 开头的 TXT 记录（如 v=spf1 / v=DMARC1）。"""
    return [t for t in records.get("TXT", []) if t.lower().startswith(prefix.lower())]


# ---------------- WHOIS (TCP/43) ----------------

_WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "cn": "whois.cnnic.cn",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "me": "whois.nic.me",
    "xyz": "whois.nic.xyz",
    "top": "whois.nic.top",
    "info": "whois.afilias.net",
    "biz": "whois.biz",
    "dev": "whois.nic.google",
    "app": "whois.nic.google",
}


def _whois_query(server: str, query: str, timeout: float = 8.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode())
        chunks: list[bytes] = []
        total = 0
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
            total += len(data)
            if total > 256 * 1024:
                break
    return b"".join(chunks).decode("utf-8", errors="replace")


def whois_lookup(domain: str, timeout: float = 8.0) -> dict:
    """WHOIS 查询 + 精简解析。返回 {server, raw, registrar, created, expires, updated, statuses, nameservers, abuse_email}。"""
    tld = domain.rsplit(".", 1)[-1].lower()
    server = _WHOIS_SERVERS.get(tld)
    if server is None:
        iana = _whois_query("whois.iana.org", domain, timeout=timeout)
        match = re.search(r"^refer:\s*(\S+)", iana, re.M | re.I)
        server = match.group(1).strip() if match else "whois.iana.org"
    raw = _whois_query(server, domain, timeout=timeout)
    return {"server": server, "raw": raw, **parse_whois(raw)}


def parse_whois(raw: str) -> dict:
    """兼容 gTLD / .cn / APNIC 风格的字段提取（找不到不报错）。"""
    def first(*patterns: str) -> str:
        for pat in patterns:
            match = re.search(pat, raw, re.M | re.I)
            if match:
                return match.group(1).strip()
        return ""

    def many(*patterns: str) -> list[str]:
        found: list[str] = []
        for pat in patterns:
            for match in re.finditer(pat, raw, re.M | re.I):
                value = match.group(1).strip()
                if value and value not in found:
                    found.append(value)
        return found

    return {
        "registrar": first(r"^\s*Registrar:\s*(.+)$", r"^\s*注册商[：:]\s*(.+)$", r"^\s*Sponsoring Registrar:\s*(.+)$"),
        "created": first(r"^\s*Creation Date:\s*(.+)$", r"^\s*Domain Registration Date:\s*(.+)$", r"^\s*Registration Time:\s*(.+)$", r"^\s*注册时间[：:]\s*(.+)$"),
        "expires": first(r"^\s*Registry Expiry Date:\s*(.+)$", r"^\s*Registrar Registration Expiration Date:\s*(.+)$", r"^\s*Expiration Time:\s*(.+)$", r"^\s*到期时间[：:]\s*(.+)$"),
        "updated": first(r"^\s*Updated Date:\s*(.+)$", r"^\s*Update Time:\s*(.+)$", r"^\s*更新时间[：:]\s*(.+)$"),
        "statuses": many(r"^\s*Domain Status:\s*(.+)$", r"^\s*Domain Status[：:]\s*(.+)$")[:8],
        "nameservers": [ns.lower() for ns in many(r"^\s*Name Server:\s*(.+)$", r"^\s*nserver:\s*(.+)$", r"^\s*Name Server[：:]\s*(.+)$")][:8],
        "abuse_email": first(r"^\s*Registrar Abuse Contact Email:\s*(.+)$", r"^\s*abuse-mailbox:\s*(.+)$"),
    }


# ---------------- RDAP ----------------

_RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1/domain/{d}",
    "net": "https://rdap.verisign.com/net/v1/domain/{d}",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/{d}",
}


def parse_rdap(data: dict) -> dict:
    """把 RDAP JSON 归一化成与 parse_whois 相同的字段风格。"""
    events = {e.get("eventAction"): e.get("eventDate") for e in data.get("events", [])}
    registrar = ""
    abuse_email = ""
    for ent in data.get("entities", []) or []:
        roles = ent.get("roles") or []
        card = (ent.get("vcardArray") or [None, []])[1] if ent.get("vcardArray") else []
        name = next((str(i[3]) for i in card if i and i[0] == "fn"), "")
        for item in card:
            if item and item[0] == "email" and len(item) > 3 and (("abuse" in roles) or not abuse_email):
                if "abuse" in roles or "abuse" in str(item[3]).lower():
                    abuse_email = str(item[3])
        if "registrar" in roles and name and not registrar:
            registrar = name
    return {
        "registrar": registrar,
        "created": events.get("registration", ""),
        "expires": events.get("expiration", ""),
        "updated": events.get("last changed", events.get("last update of RDAP database", "")),
        "statuses": [str(s) for s in data.get("status", [])][:8],
        "nameservers": [str(ns.get("ldhName", "")).lower() for ns in data.get("nameservers", []) if ns.get("ldhName")][:8],
        "abuse_email": abuse_email,
    }


def rdap_domain(domain: str, client: HttpClient) -> dict | None:
    """按 TLD 走已知 RDAP 端点；无映射或失败返回 None（调用方退回 WHOIS）。"""
    tld = domain.rsplit(".", 1)[-1].lower()
    template = _RDAP_SERVERS.get(tld)
    if not template:
        return None
    resp = client.get(template.format(d=domain), timeout=6, retries=0)
    if resp.status_code != 200:
        raise RuntimeError(f"RDAP HTTP {resp.status_code}")
    data = resp.json()
    return {"server": template.split("/")[2], **parse_rdap(data)}


# ---------------- TLS ----------------

def tls_info(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """直连取证书信息（不做信任链校验，只读公开证书）。"""
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    subject = {k: v for item in cert.get("subject", []) for k, v in item}
    issuer = {k: v for item in cert.get("issuer", []) for k, v in item}
    not_after = cert.get("notAfter", "")
    days_left = None
    if not_after:
        try:
            expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expires - datetime.now(timezone.utc)).days
        except Exception:  # noqa: BLE001
            pass
    san = [entry[1] for entry in cert.get("subjectAltName", []) if entry[0] == "DNS"]
    return {
        "subject": subject.get("commonName", ""),
        "issuer": issuer.get("organizationName") or issuer.get("commonName", ""),
        "not_after": not_after,
        "days_left": days_left,
        "san_count": len(san),
        "san_sample": san[:8],
        "tls_version": version,
    }


# ---------------- HIBP（密码泄露自查） ----------------

def pwned_password_count(password: str, client: HttpClient) -> int:
    """k-匿名查询：只发送 SHA-1 前 5 位，其余比对全部在本机完成。"""
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    resp = client.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true"},
        timeout=8,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HIBP HTTP {resp.status_code}")
    for line in resp.text.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0].upper() == suffix:
            return int(parts[1])
    return 0


# ---------------- 证书透明度 / 主机发现 ----------------

def certspotter_subdomains(domain: str, client: HttpClient, limit: int = 300) -> list[str]:
    resp = client.get(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"CertSpotter HTTP {resp.status_code}")
    names: set[str] = set()
    for item in resp.json() or []:
        for name in item.get("dns_names") or []:
            name = str(name).lower().lstrip("*.")
            if name and name.endswith(domain):
                names.add(name)
            if len(names) >= limit:
                break
    return sorted(names)[:limit]


def hackertarget_hosts(domain: str, client: HttpClient, limit: int = 300) -> list[str]:
    resp = client.get(
        "https://api.hackertarget.com/hostsearch/",
        params={"q": domain},
        timeout=10,
    )
    if resp.status_code != 200:
        raise RuntimeError(f"HackerTarget HTTP {resp.status_code}")
    body = resp.text or ""
    if "API count exceeded" in body or "error" in body.lower()[:80]:
        raise RuntimeError(f"HackerTarget 限流/错误: {body[:80]}")
    names: set[str] = set()
    for line in body.splitlines():
        host = line.split(",")[0].strip().lower()
        if host and host.endswith(domain):
            names.add(host)
    return sorted(names)[:limit]


def _parse_date(text: str) -> datetime | None:
    if not text:
        return None
    cleaned = text.strip().replace("Z", "").replace("T", " ")
    for cand in (cleaned, cleaned[:19], cleaned[:16], cleaned[:10]):
        for fmt in (
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d",
            "%Y.%m.%d", "%Y/%m/%d", "%d-%b-%Y", "%Y%m%d",
        ):
            try:
                return datetime.strptime(cand, fmt)
            except ValueError:
                continue
    return None


def fmt_age(created: str) -> str:
    """把注册时间粗略格式化为 'X 年 Y 天'（解析失败返回空串）。"""
    when = _parse_date(created)
    if not when:
        return ""
    days = (datetime.now() - when).days
    if days < 0:
        return ""
    return f"{days // 365} 年 {days % 365} 天" if days >= 365 else f"{days} 天"
