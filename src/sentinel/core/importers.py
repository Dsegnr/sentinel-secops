"""扫描结果导入：把第三方工具输出转换为「发现」。

支持：nuclei JSONL（nuclei -jsonl）与通用 CSV（title,severity,target,detail）。
仅导入本地文件；导入前请确认扫描行为已获授权。
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
from pathlib import Path

from .assets import AssetStore
from .findings import FindingStore
from .notify import notify_min_severity, notify_summary, severity_at_least

_SEVS = {"info", "low", "medium", "high", "critical"}


def _norm_sev(value: str) -> str:
    value = (value or "").strip().lower()
    return value if value in _SEVS else "info"


def _asset_type_for(host: str) -> str:
    host = (host or "").strip()
    try:
        ipaddress.ip_address(host)
        return "ip"
    except ValueError:
        pass
    return "domain" if "." in host else "other"


def parse_nuclei_jsonl(text: str) -> list[dict]:
    items: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = obj.get("info") or {}
        name = info.get("name") or obj.get("template-id") or "nuclei 结果"
        host = str(obj.get("host") or obj.get("matched-at") or "")
        items.append(
            {
                "title": f"[nuclei] {name} @ {host}"[:180],
                "severity": _norm_sev(str(info.get("severity") or "")),
                "target": host,
                "detail": json.dumps(
                    {
                        "template": obj.get("template-id"),
                        "matched-at": obj.get("matched-at"),
                        "type": obj.get("type"),
                    },
                    ensure_ascii=False,
                ),
            }
        )
    return items


def parse_csv(text: str) -> list[dict]:
    items: list[dict] = []
    reader = csv.DictReader(io.StringIO(text))
    for row in reader:
        title = (row.get("title") or row.get("name") or "").strip()
        if not title:
            continue
        items.append(
            {
                "title": title[:180],
                "severity": _norm_sev(row.get("severity", "")),
                "target": (row.get("target") or row.get("host") or "").strip(),
                "detail": (row.get("detail") or row.get("description") or "").strip(),
            }
        )
    return items


def detect_format(path: Path) -> str:
    return "csv" if Path(path).suffix.lower() == ".csv" else "nuclei"


def import_file(path: Path, fmt: str, findings: FindingStore, assets: AssetStore) -> dict:
    text = Path(path).read_text(encoding="utf-8-sig", errors="ignore")
    fmt = (fmt or "auto").lower()
    if fmt == "auto":
        fmt = detect_format(Path(path))
    if fmt == "nuclei":
        items = parse_nuclei_jsonl(text)
    elif fmt == "csv":
        items = parse_csv(text)
    else:
        raise ValueError(f"不支持的格式: {fmt}")

    stats = {"total": len(items), "imported": 0, "skipped": 0}
    notable: list[dict] = []
    existing_titles = {f.get("title") for f in findings.list() if f.get("status") != "closed"}
    for item in items:
        if item["title"] in existing_titles:
            stats["skipped"] += 1
            continue
        asset_id = None
        target = item.get("target") or ""
        if target:
            host = target.split("//")[-1].split("/")[0].split(":")[0]
            if host:
                asset = assets.upsert(_asset_type_for(host), host)
                asset_id = asset["id"]
        finding = findings.create(
            item["title"],
            severity=item["severity"],
            detail=item.get("detail", ""),
            source="import",
            asset=asset_id,
        )
        if severity_at_least(item["severity"], notify_min_severity()):
            notable.append(finding)
        existing_titles.add(item["title"])
        stats["imported"] += 1
    if notable:
        lines = [f"{f['severity']} · {f['title']}" for f in notable[:5]]
        if len(notable) > 5:
            lines.append(f"…等共 {len(notable)} 条")
        notify_summary("[Sentinel] 导入新发现", lines)
    return stats
