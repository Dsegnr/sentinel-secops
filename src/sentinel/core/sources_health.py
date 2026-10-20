"""数据源健康检测：对工作台运行时实际依赖的公开源逐个探活。

与 checks/probe_public_sources.py（全量盘点，含历史淘汰端点）不同：
这里只包含"运行时真正会用到"的源，供工作台「数据源健康」页与巡检任务调用。
只做只读 GET / TCP 连接，不写任何远端数据。
"""

from __future__ import annotations

import socket
import time
from datetime import datetime
from pathlib import Path

import requests

UA = {"User-Agent": "Sentinel-SecOps/0.1 (source health; public data only)"}

# SPEC: kind=http -> url/params/headers/timeout/stream；kind=tcp -> host/port/query
PROBES: list[dict] = [
    {"name": "360 号码库", "kind": "http", "url": "https://cx.shouji.360.cn/phonearea.php",
     "params": {"number": "13800138000"}, "timeout": 8},
    {"name": "ipwho.is", "kind": "http", "url": "https://ipwho.is/8.8.8.8", "timeout": 12},
    {"name": "ip-api.com", "kind": "http", "url": "http://ip-api.com/json/8.8.8.8",
     "params": {"lang": "zh-CN"}, "timeout": 8},
    {"name": "Shodan InternetDB", "kind": "http", "url": "https://internetdb.shodan.io/8.8.8.8", "timeout": 8},
    {"name": "ISC DShield", "kind": "http", "url": "https://isc.sans.edu/api/ip/8.8.8.8",
     "params": {"json": ""}, "timeout": 8},
    {"name": "blocklist.de", "kind": "http", "url": "https://api.blocklist.de/api.php",
     "params": {"ip": "8.8.8.8"}, "timeout": 14},
    {"name": "RIPEstat", "kind": "http", "url": "https://stat.ripe.net/data/network-info/data.json",
     "params": {"resource": "8.8.8.8"}, "timeout": 8},
    {"name": "urlscan.io", "kind": "http", "url": "https://urlscan.io/api/v1/search/",
     "params": {"q": "domain:example.com", "size": "1"}, "timeout": 8},
    {"name": "RDAP Verisign", "kind": "http", "url": "https://rdap.verisign.com/com/v1/domain/example.com", "timeout": 8},
    {"name": "RDAP APNIC", "kind": "http", "url": "https://rdap.apnic.net/ip/1.1.1.1", "timeout": 8},
    {"name": "CertSpotter", "kind": "http", "url": "https://api.certspotter.com/v1/issuances",
     "params": {"domain": "example.com", "include_subdomains": "true", "expand": "dns_names"}, "timeout": 10},
    {"name": "HackerTarget", "kind": "http", "url": "https://api.hackertarget.com/hostsearch/",
     "params": {"q": "example.com"}, "timeout": 10},
    {"name": "HIBP PwnedPasswords", "kind": "http", "url": "https://api.pwnedpasswords.com/range/5BAA6",
     "timeout": 8, "stream": True},
    {"name": "FireHOL(jsDelivr)", "kind": "http",
     "url": "https://cdn.jsdelivr.net/gh/firehol/blocklist-ipsets@master/firehol_level1.netset",
     "timeout": 20, "stream": True},
    {"name": "Spamhaus DROP", "kind": "http", "url": "https://www.spamhaus.org/drop/drop.txt",
     "timeout": 15, "stream": True},
    {"name": "whois.verisign-grs", "kind": "tcp", "host": "whois.verisign-grs.com", "port": 43, "query": "example.com"},
    {"name": "whois.cnnic", "kind": "tcp", "host": "whois.cnnic.cn", "port": 43, "query": "example.cn"},
]


def _session() -> requests.Session:
    session = requests.Session()
    session.headers.update(UA)
    return session


def probe_http(spec: dict, session) -> dict:
    started = time.perf_counter()
    row: dict = {"name": spec["name"], "kind": "http"}
    try:
        resp = session.get(
            spec["url"],
            params=spec.get("params"),
            headers=spec.get("headers"),
            timeout=spec.get("timeout", 10),
            stream=spec.get("stream", False),
            allow_redirects=True,
        )
        row["status"] = resp.status_code
        if spec.get("stream"):
            chunk = next(resp.iter_content(300), b"")
            text = chunk.decode("utf-8", errors="replace")
        else:
            text = (resp.text or "")[:500]
        row["sample"] = " ".join(text.split())[:120]
        row["ok"] = resp.status_code == 200 and bool(text.strip())
    except Exception as exc:  # noqa: BLE001
        row["status"] = None
        row["ok"] = False
        row["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    row["ms"] = int((time.perf_counter() - started) * 1000)
    return row


def probe_tcp(spec: dict) -> dict:
    started = time.perf_counter()
    row: dict = {"name": spec["name"], "kind": "tcp"}
    try:
        with socket.create_connection((spec["host"], spec.get("port", 43)), timeout=spec.get("timeout", 8)) as sock:
            sock.sendall((spec.get("query", "") + "\r\n").encode())
            data = sock.recv(512)
        row["status"] = 200
        row["sample"] = " ".join(data.decode("utf-8", errors="replace").split())[:120]
        row["ok"] = len(data) > 0
    except Exception as exc:  # noqa: BLE001
        row["status"] = None
        row["ok"] = False
        row["error"] = f"{type(exc).__name__}: {str(exc)[:120]}"
    row["ms"] = int((time.perf_counter() - started) * 1000)
    return row


def run_checks(session=None, probes: list[dict] | None = None) -> dict:
    session = session or _session()
    probes = probes if probes is not None else PROBES
    results = []
    for spec in probes:
        results.append(probe_tcp(spec) if spec.get("kind") == "tcp" else probe_http(spec, session))
    return {
        "when": datetime.now().isoformat(timespec="seconds"),
        "total": len(results),
        "ok": sum(1 for r in results if r.get("ok")),
        "results": results,
    }


def load_health(path: Path) -> dict | None:
    """读取最近一次健康结果（工作台总览 / 数据源页共用）。"""
    import json

    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None
