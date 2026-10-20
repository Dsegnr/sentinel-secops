"""案件落档：报告.md + report.json + manifest.json（SHA-256 证据清单）。

目录形态：cases/<时间>-<类型>-<目标>/，用于后续举报 / 报案的完整性校验。
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path

from .models import TriageReport

ARCHIVE_DIRNAME = ".archive"


def _safe(name: str) -> str:
    return re.sub(r"[^0-9A-Za-z._+-]", "_", name)[:64] or "unknown"


def render_markdown(report: TriageReport) -> str:
    lines = [
        f"# 研判报告 · {report.kind} · {report.target}",
        "",
        f"- 生成时间：{report.created_at}",
        "- 数据源：公开数据 / 本机离线解析；未经授权不得用于对个人的骚扰或曝光",
        "",
        "## 结论字段",
        "",
        "| 字段 | 值 | 置信度 | 来源 |",
        "| --- | --- | --- | --- |",
    ]
    for f in report.findings:
        lines.append(f"| {f.key} | {f.value} | {f.confidence.value} | {f.source} |")
    lines += ["", "## 数据源状态", "", "| 数据源 | 状态 | 说明 |", "| --- | --- | --- |"]
    for s in report.sources:
        lines.append(f"| {s.source} | {'OK' if s.ok else 'FAIL'} | {s.detail or s.error} |")
    if report.notes:
        lines += ["", "## 备注", ""] + [f"- {n}" for n in report.notes]
    lines += ["", "---", "", "本报告仅基于公开数据源生成，用于防御与合法维权取证。"]
    return "\n".join(lines)


def save_case(report: TriageReport, cases_dir: Path) -> Path:
    stamp = report.created_at.replace(":", "").replace("-", "")[:15]
    case_dir = Path(cases_dir) / f"{stamp}-{report.kind}-{_safe(report.target)}"
    case_dir.mkdir(parents=True, exist_ok=True)

    (case_dir / "report.json").write_text(report.to_json(), encoding="utf-8")
    (case_dir / "report.md").write_text(render_markdown(report), encoding="utf-8")

    manifest = {
        "case": case_dir.name,
        "created_at": report.created_at,
        "kind": report.kind,
        "target": report.target,
        "files": [
            {"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(case_dir.iterdir())
            if p.is_file()
        ],
        "note": "证据清单（SHA-256），用于举报/报案材料的完整性校验。",
    }
    (case_dir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return case_dir


def filter_cases(items: list[dict], q: str = "", kind: str = "") -> list[dict]:
    """按类型与关键字（案件名 / 目标，大小写不敏感）过滤案件列表。"""
    keyword = (q or "").strip().lower()
    wanted_kind = (kind or "").strip().lower()
    out: list[dict] = []
    for item in items:
        if wanted_kind and str(item.get("kind", "")).lower() != wanted_kind:
            continue
        if keyword:
            haystack = f"{item.get('name', '')} {item.get('target', '')}".lower()
            if keyword not in haystack:
                continue
        out.append(item)
    return out


def _archive_dir(cases_dir: Path) -> Path:
    return Path(cases_dir) / ARCHIVE_DIRNAME


def _safe_name(name: str) -> str:
    text = (name or "").strip()
    if not text or "/" in text or "\\" in text or text.startswith("."):
        return ""
    return text


def archive_cases(cases_dir: Path, names: list[str]) -> dict:
    """把案件目录移入 .archive（可恢复）。返回 {archived: [...], skipped: [...]}。"""
    cases_dir = Path(cases_dir)
    archive = _archive_dir(cases_dir)
    archive.mkdir(parents=True, exist_ok=True)
    archived: list[str] = []
    skipped: list[str] = []
    for raw in names:
        name = _safe_name(raw)
        source = cases_dir / name if name else None
        if not name or not source.is_dir():
            skipped.append(str(raw))
            continue
        target = archive / name
        if target.exists():
            skipped.append(f"{name}（归档中已存在）")
            continue
        shutil.move(str(source), str(target))
        archived.append(name)
    return {"archived": archived, "skipped": skipped}


def restore_cases(cases_dir: Path, names: list[str]) -> dict:
    """把归档案件移回 cases/。返回 {restored: [...], skipped: [...]}。"""
    cases_dir = Path(cases_dir)
    archive = _archive_dir(cases_dir)
    restored: list[str] = []
    skipped: list[str] = []
    for raw in names:
        name = _safe_name(raw)
        source = archive / name if name else None
        if not name or not source.is_dir():
            skipped.append(str(raw))
            continue
        target = cases_dir / name
        if target.exists():
            skipped.append(f"{name}（cases 中已存在同名目录）")
            continue
        shutil.move(str(source), str(target))
        restored.append(name)
    return {"restored": restored, "skipped": skipped}


def delete_archived(cases_dir: Path, names: list[str], confirm: str = "") -> dict:
    """永久删除归档中的案件（不可恢复）。必须显式传入 confirm="DELETE"；只作用于 .archive 内。"""
    cases_dir = Path(cases_dir)
    archive = _archive_dir(cases_dir)
    if confirm != "DELETE":
        return {"deleted": [], "skipped": [f"{n}（缺少删除确认）" for n in names]}
    deleted: list[str] = []
    skipped: list[str] = []
    for raw in names:
        name = _safe_name(raw)
        target = archive / name if name else None
        if not name or not target.is_dir():
            skipped.append(str(raw))
            continue
        # 双重确认：解析后必须仍位于 .archive 之内
        try:
            if not target.resolve().is_relative_to(archive.resolve()):
                skipped.append(f"{name}（路径校验失败）")
                continue
        except OSError:
            skipped.append(f"{name}（路径校验失败）")
            continue
        shutil.rmtree(target)
        deleted.append(name)
    return {"deleted": deleted, "skipped": skipped}


def grep_cases(
    cases_dir: Path,
    items: list[dict],
    keyword: str,
    limit: int = 50,
    read_bytes: int = 65536,
) -> list[dict]:
    """在案件报告正文（report.md / report.json）中检索关键字，返回带 snippet 的条目。"""
    kw = (keyword or "").strip().lower()
    if not kw:
        return []
    cases_dir = Path(cases_dir)
    hits: list[dict] = []
    for item in items:
        name = str(item.get("name") or "")
        if not name:
            continue
        case_dir = cases_dir / name
        parts: list[str] = []
        for fname in ("report.md", "report.json"):
            path = case_dir / fname
            if not path.is_file():
                continue
            try:
                parts.append(path.read_text(encoding="utf-8", errors="ignore")[:read_bytes])
            except Exception:  # noqa: BLE001
                continue
        text = "\n".join(parts)
        index = text.lower().find(kw)
        if index < 0:
            continue
        start = max(0, index - 40)
        end = min(len(text), index + len(kw) + 80)
        snippet = " ".join(text[start:end].split())
        hits.append({**item, "snippet": snippet})
        if len(hits) >= limit:
            break
    return hits
