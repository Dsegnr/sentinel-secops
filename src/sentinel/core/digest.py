"""每日摘要：案件 / 发现 / 基线 / 封堵 / 数据源 / 巡检 一页概览（可推送 webhook）。

数据全部来自本机既有产物：cases/、data/、checks/out/（baseline / sources-health / tasks）。
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta
from pathlib import Path

from .blocklist import BlocklistStore
from .findings import SEVERITIES, FindingStore
from .posture import baseline_issues, diff_baselines


def _recent_case_stats(cases_dir: Path, hours: int) -> dict:
    cutoff = time.time() - hours * 3600
    recent = 0
    kinds: dict[str, int] = {}
    if cases_dir.is_dir():
        for case in cases_dir.iterdir():
            if not case.is_dir():
                continue
            try:
                if case.stat().st_mtime < cutoff:
                    continue
            except OSError:
                continue
            recent += 1
            kind = "-"
            report_json = case / "report.json"
            if report_json.is_file():
                try:
                    kind = str(json.loads(report_json.read_text(encoding="utf-8")).get("kind", "-"))
                except Exception:  # noqa: BLE001
                    pass
            kinds[kind] = kinds.get(kind, 0) + 1
    return {"recent": recent, "kinds": kinds}


def build_digest(root: Path, hours: int = 24) -> dict:
    root = Path(root)
    out_dir = root / "checks" / "out"

    findings = FindingStore(root / "data").list()
    open_items = [f for f in findings if f.get("status") != "closed"]
    by_severity: dict[str, int] = {}
    for item in open_items:
        key = str(item.get("severity", "info"))
        by_severity[key] = by_severity.get(key, 0) + 1
    cutoff = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")
    new_items = [f for f in findings if str(f.get("created_at", "")) >= cutoff]
    top_open = sorted(open_items, key=lambda f: SEVERITIES.index(str(f.get("severity", "info"))) if str(f.get("severity", "info")) in SEVERITIES else 0, reverse=True)

    baseline = None
    files = sorted(out_dir.glob("baseline-*.json")) if out_dir.is_dir() else []
    if files:
        try:
            latest = json.loads(files[-1].read_text(encoding="utf-8"))
            diff_changes = 0
            if len(files) > 1:
                prev = json.loads(files[-2].read_text(encoding="utf-8"))
                diff = diff_baselines(prev, latest)
                diff_changes = sum(
                    len(item.get("added") or []) + len(item.get("removed") or [])
                    for item in diff.values()
                )
            baseline = {
                "file": files[-1].name,
                "captured": latest.get("capturedAt"),
                "issues": baseline_issues(latest),
                "diff_changes": diff_changes,
            }
        except Exception:  # noqa: BLE001
            baseline = {"file": files[-1].name, "error": "解析失败", "issues": [], "diff_changes": 0}

    store = BlocklistStore(root / "data")
    blocklist = {"age_hours": store.age_hours(), "sources": store.stats()}

    health = None
    health_path = out_dir / "sources-health.json"
    if health_path.is_file():
        try:
            data = json.loads(health_path.read_text(encoding="utf-8"))
            health = {"when": data.get("when"), "ok": data.get("ok"), "total": data.get("total")}
        except Exception:  # noqa: BLE001
            pass

    last_patrol = None
    tasks_path = out_dir / "tasks.json"
    if tasks_path.is_file():
        try:
            tasks = json.loads(tasks_path.read_text(encoding="utf-8"))
            last = next(
                (t for t in reversed(tasks) if t.get("kind") == "patrol" and t.get("status") in ("done", "failed")),
                None,
            )
            if last:
                last_patrol = {"status": last.get("status"), "finished": last.get("finished"), "result": last.get("result")}
        except Exception:  # noqa: BLE001
            pass

    return {
        "when": datetime.now().isoformat(timespec="seconds"),
        "window_hours": hours,
        "cases": _recent_case_stats(root / "cases", hours),
        "findings": {
            "open": len(open_items),
            "by_severity": by_severity,
            "new": len(new_items),
            "top": [{"title": f.get("title"), "severity": f.get("severity")} for f in top_open[:3]],
        },
        "baseline": baseline,
        "blocklist": blocklist,
        "health": health,
        "last_patrol": last_patrol,
    }


def render_text(digest: dict) -> str:
    """推送用纯文本摘要（也用于页面折叠展示）。"""
    lines = [f"【Sentinel 每日摘要】{str(digest.get('when', ''))[:16].replace('T', ' ')}（近 {digest.get('window_hours', 24)} 小时）"]

    cases = digest.get("cases") or {}
    kind_text = "、".join(f"{k}×{v}" for k, v in (cases.get("kinds") or {}).items())
    lines.append(f"案件：新增 {cases.get('recent', 0)} 个" + (f"（{kind_text}）" if kind_text else ""))

    findings = digest.get("findings") or {}
    severity_text = "、".join(f"{k}×{v}" for k, v in (findings.get("by_severity") or {}).items()) or "无"
    lines.append(f"发现：待处理 {findings.get('open', 0)}（{severity_text}），近 24h 新增 {findings.get('new', 0)}")
    for item in findings.get("top") or []:
        lines.append(f"  - 待处理重点：[{item.get('severity')}] {item.get('title')}")

    baseline = digest.get("baseline")
    if baseline:
        lines.append(
            f"基线：{baseline.get('captured') or baseline.get('file')} · 待加固 {len(baseline.get('issues') or [])} 项 · 较上版变化 {baseline.get('diff_changes', 0)} 处"
        )
    else:
        lines.append("基线：尚未体检（可到总览点一次体检）")

    age = (digest.get("blocklist") or {}).get("age_hours")
    lines.append("封堵清单：" + ("尚未同步" if age is None else f"{age:.0f} 小时前更新"))

    health = digest.get("health")
    if health:
        lines.append(f"数据源：{health.get('ok')}/{health.get('total')} 可用（{str(health.get('when', ''))[:16]}）")
    else:
        lines.append("数据源：尚未检测")

    patrol = digest.get("last_patrol")
    if patrol:
        lines.append(f"最近巡检：{patrol.get('finished', '-')} {patrol.get('status', '-')}")
    else:
        lines.append("最近巡检：未运行")
    return "\n".join(lines)
