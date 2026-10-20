"""用户名跨平台探活：YAML 平台清单 + 线程池并发 + 三级判定（存在/未发现/无法判定）。

判定引擎（与 Sherlock / Maigret 的规则体系对齐，均 MIT 许可）：
  1. 状态码在 missing_status（默认 404）          -> missing
  2. 正文命中 missing_markers（absent 特征串）     -> missing
  3. 正文命中 present_markers（存在特征串）        -> exists
  4. 定义了 present_markers 但均未命中            -> unknown（宁缺勿假）
  5. 状态码在 ok_status（默认 200）且无特征串要求  -> exists
  6. 其余                                         -> unknown
"""

from __future__ import annotations

import concurrent.futures as cf
import hashlib
import re
from pathlib import Path
from urllib.parse import quote

import yaml

from ..core.http import HttpClient
from ..core.models import Confidence, SourceResult, TriageReport

_WORKERS = 12

_BAD_CHARS = re.compile(r"[\s/\\?#%&=:\"'<>@]")

# 实测（2026-10-11）：多个"几乎必然未分配"的 10 位号码，头像字节完全一致
_QQ_DEFAULT_AVATAR_MD5 = "4700116072a9"


def handle_ok(value: str) -> bool:
    """用户名 / ID 合法性：允许各类 Unicode（含中文），拒绝空白与 URL 破坏字符，1-64 位。"""
    value = (value or "").strip()
    if not (1 <= len(value) <= 64):
        return False
    return _BAD_CHARS.search(value) is None


def _load_platforms(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return [p for p in data.get("platforms", []) if p.get("enabled", True)]


def check_platform(platform: dict, username: str, client: HttpClient) -> dict:
    """对单个平台执行一次探活，返回 {state: exists|missing|unknown, status, note}。"""
    custom = platform.get("check")
    if custom and custom in _CUSTOM_CHECKS:
        return _CUSTOM_CHECKS[custom](platform, username, client)
    url = platform["url"].format(u=quote(username, safe="-._"))
    try:
        resp = client.get(
            url,
            allow_redirects=platform.get("allow_redirects", True),
            timeout=float(platform.get("timeout") or getattr(client, "timeout", 8) or 8),
        )
        body = resp.text or ""
        present = [m for m in platform.get("present_markers", []) if re.search(m, body, re.I | re.S)]
        missing = [m for m in platform.get("missing_markers", []) if re.search(m, body, re.I | re.S)]
        ok_status = platform.get("ok_status", [200])
        missing_status = platform.get("missing_status", [404])

        if resp.status_code in missing_status:
            state = "missing"
        elif missing:
            state = "missing"
        elif present:
            state = "exists"
        elif platform.get("present_markers"):
            state = "unknown"  # 有特征要求但都没出现：规则未覆盖，不妄断
        elif resp.status_code in ok_status:
            state = "exists"
        else:
            state = "unknown"
        return {
            "name": platform["name"],
            "category": platform.get("category", "其他"),
            "url": url,
            "state": state,
            "status": resp.status_code,
            "note": platform.get("note", ""),
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "name": platform["name"],
            "category": platform.get("category", "其他"),
            "url": url,
            "state": "unknown",
            "status": None,
            "note": f"无法访问: {str(exc)[:80]}",
        }


def _base_result(platform: dict, url: str) -> dict:
    return {
        "name": platform["name"],
        "category": platform.get("category", "其他"),
        "url": url,
        "state": "unknown",
        "status": None,
        "note": platform.get("note", ""),
    }


def _check_qq_avatar(platform: dict, username: str, client: HttpClient) -> dict:
    """QQ 头像探活：有公开头像=存在；默认头像=无法判定（未注册或未设头像）。"""
    url = platform["url"].format(u=username)
    result = _base_result(platform, url)
    if not (username.isdigit() and 5 <= len(username) <= 12):
        result["note"] = "QQ 号应为 5-12 位数字"
        return result
    try:
        resp = client.get(url, timeout=8, retries=0)
        result["status"] = resp.status_code
        if resp.status_code != 200:
            return result
        digest = hashlib.md5(resp.content).hexdigest()[:12]
        if digest == _QQ_DEFAULT_AVATAR_MD5:
            result["note"] = "默认头像：可能未注册，也可能未设置头像（无法判定）"
        else:
            result["state"] = "exists"
            result["note"] = "存在公开头像（该 QQ 号有效）"
        return result
    except Exception as exc:  # noqa: BLE001
        result["note"] = f"无法访问: {str(exc)[:80]}"
        return result


_CUSTOM_CHECKS = {"qq_avatar": _check_qq_avatar}


def triage(
    target: str,
    client: HttpClient,
    platforms_path: Path,
    only: list[str] | None = None,
) -> TriageReport:
    rep = TriageReport(kind="username", target=target)
    platforms = _load_platforms(platforms_path)
    if only:
        wanted = {re.sub(r"\s+", "", s).lower() for s in only}
        platforms = [
            p for p in platforms if re.sub(r"\s+", "", str(p["name"])).lower() in wanted
        ]
    if not platforms:
        rep.add("平台清单", "为空（检查 --only 或 platforms.yaml）", Confidence.UNAVAILABLE, "内置")
        return rep

    with cf.ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        futures = [pool.submit(check_platform, p, target, client) for p in platforms]
        results = [f.result() for f in cf.as_completed(futures)]

    order = {p["name"]: i for i, p in enumerate(platforms)}
    results.sort(key=lambda r: order.get(r["name"], 999))

    hits = misses = unknowns = 0
    hit_names: list[str] = []
    cat_stats: dict[str, list[int]] = {}
    for r in results:
        cat = r["category"]
        cat_stats.setdefault(cat, [0, 0, 0])
        if r["state"] == "exists":
            hits += 1
            hit_names.append(f"{r['name']}（{cat}）")
            cat_stats[cat][0] += 1
            rep.add(f"[存在] {r['name']}", r["url"], Confidence.LIKELY, f"公开页面探活·{cat}")
            rep.sources.append(SourceResult(r["name"], True, f"HTTP {r['status']} 命中"))
        elif r["state"] == "missing":
            misses += 1
            cat_stats[cat][1] += 1
            rep.sources.append(SourceResult(r["name"], True, f"HTTP {r['status']} 未命中"))
        else:
            unknowns += 1
            cat_stats[cat][2] += 1
            rep.sources.append(
                SourceResult(r["name"], False, error=r["note"] or f"HTTP {r['status']} 无法判定")
            )

    rep.add(
        "探活统计",
        f"存在 {hits} / 未发现 {misses} / 无法判定 {unknowns}（共 {len(results)} 平台）",
        Confidence.CONFIRMED,
        "内置",
    )
    if hit_names:
        rep.add(
            "命中列表",
            "、".join(hit_names[:40]) + ("…" if len(hit_names) > 40 else ""),
            Confidence.LIKELY,
            "内置",
        )
    for cat, (h, m, u) in sorted(cat_stats.items()):
        rep.add(f"分类·{cat}", f"存在 {h} / 未发现 {m} / 无法判定 {u}", Confidence.UNVERIFIED, "内置")
    rep.note("同名 != 同一人：常见昵称撞名严重，需结合公开资料人工交叉核验。")
    rep.note("'无法判定'多为网络不可达或被反爬拦截，绝不等同于'不存在'。")
    rep.note("平台清单整理自 Sherlock / Maigret（MIT）数据并逐一实机验证；仅探测公开主页。")
    return rep
