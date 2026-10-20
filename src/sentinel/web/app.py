"""Sentinel 工作台：本地 Web 控制台（默认仅监听 127.0.0.1）。

页面：总览 / 一键研判（电话·IP·社交足迹）/ 知识库 / 工具目录 / 案件库。
所有数据来自本机项目目录：cases/（案件）、kb/（知识库）、checks/out/（体检输出）。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.parse import quote

import markdown
import yaml
from fastapi import FastAPI, Form, HTTPException, Query
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..core.ai import AIError, ai_available, summarize_report
from ..core.assets import ASSET_TYPES, AssetStore, kind_to_type
from ..core.batch import BATCH_KINDS, parse_targets
from ..core.blocklist import BlocklistStore
from ..core.case import (
    ARCHIVE_DIRNAME,
    archive_cases,
    delete_archived,
    filter_cases,
    grep_cases,
    restore_cases,
    save_case,
)
from ..core.config import load_config, project_root
from ..core.export import export_case
from ..core.findings import SEVERITIES, STATUSES, FindingStore
from ..core import hardening
from ..core.http import HttpClient, inject_os_truststore
from ..core.importers import import_file
from ..core.notify import notify_finding
from ..core.pack import build_package
from ..core.posture import baseline_issues, diff_baselines
from ..core.search import build_search_links
from ..core.sources_health import load_health
from ..core.tasks import TaskManager
from ..modules import ip as ip_mod
from ..modules import phone as phone_mod
from ..modules import username as user_mod
from ..modules import breach as breach_mod
from ..modules import domain as domain_mod
from ..modules import emailhdr as email_mod
from ..modules import mailbox as mailbox_mod
from ..modules import url as url_mod

WEB_DIR = Path(__file__).resolve().parent
ROOT = project_root()
KB_ROOT = ROOT / "kb"
CASES_DIR = ROOT / "cases"
OUT_DIR = ROOT / "checks" / "out"
POSTURE_SCRIPT = ROOT / "checks" / "posture_windows.ps1"
PLATFORMS = WEB_DIR.parent / "data" / "platforms.yaml"

inject_os_truststore()

_env = Environment(
    loader=FileSystemLoader(WEB_DIR / "templates"),
    autoescape=select_autoescape(["html"]),
)
_env.globals["version"] = __version__

_STYLE_FILE = WEB_DIR / "static" / "style.css"


def _static_v() -> str:
    """样式表缓存版本号：取文件 mtime，改样式即换 URL（绕开浏览器旧缓存）。"""
    try:
        return str(int(_STYLE_FILE.stat().st_mtime))
    except OSError:
        return "0"


_env.globals["static_v"] = _static_v

app = FastAPI(title="Sentinel 工作台", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
TASKS = TaskManager(ROOT)
ASSETS = AssetStore(ROOT / "data")
FINDINGS = FindingStore(ROOT / "data")
BLOCKLIST = BlocklistStore(ROOT / "data")
_TRY_KINDS = {"phone", "ip", "user", "domain", "url", "breach", "email", "mailbox"}
_monitor_cfg: dict = {}
try:
    _monitor_cfg = load_config().get("monitor") or {}
    if _monitor_cfg.get("enabled"):
        TASKS.enable_schedule(float(_monitor_cfg.get("interval_hours", 12) or 12))
except Exception:  # noqa: BLE001
    pass


def render(template: str, **ctx) -> HTMLResponse:
    return HTMLResponse(_env.get_template(template).render(**ctx))


def _client() -> HttpClient:
    cfg = load_config()
    return HttpClient(
        timeout=float(cfg.get("timeout", 8) or 8),
        proxy=(cfg.get("proxy") or "").strip() or None,
    )


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def _md(text: str) -> str:
    return markdown.markdown(text, extensions=["tables", "fenced_code"])


def _report_ctx(report) -> dict:
    return {
        "kind": report.kind,
        "target": report.target,
        "created_at": report.created_at,
        "findings": [
            {"key": f.key, "value": f.value, "conf": f.confidence.value, "source": f.source}
            for f in report.findings
        ],
        "sources": [
            {"source": s.source, "ok": s.ok, "note": s.detail or s.error}
            for s in report.sources
        ],
        "notes": list(report.notes),
    }


def _report_ctx_dict(data: dict) -> dict:
    return {
        "kind": data.get("kind", "-"),
        "target": data.get("target", "-"),
        "created_at": data.get("created_at", "-"),
        "findings": [
            {
                "key": item.get("key"),
                "value": item.get("value"),
                "conf": item.get("confidence"),
                "source": item.get("source"),
            }
            for item in (data.get("findings") or [])
        ],
        "sources": [
            {"source": item.get("source"), "ok": item.get("ok"), "note": item.get("detail") or item.get("error")}
            for item in (data.get("sources") or [])
        ],
        "notes": list(data.get("notes") or []),
    }


# ---------------- 案件 ----------------

def _verify_manifest(case_dir: Path) -> list[dict]:
    rows: list[dict] = []
    manifest = case_dir / "manifest.json"
    if not manifest.is_file():
        return rows
    try:
        data = json.loads(_read_text(manifest))
    except Exception:
        return rows
    for item in data.get("files", []):
        path = case_dir / str(item.get("path", ""))
        ok = False
        if path.is_file():
            ok = hashlib.sha256(path.read_bytes()).hexdigest() == item.get("sha256")
        rows.append({"path": item.get("path"), "ok": ok})
    return rows


def _case_info(case_dir: Path) -> dict:
    info = {
        "name": case_dir.name,
        "created": datetime.fromtimestamp(case_dir.stat().st_mtime).strftime("%m-%d %H:%M"),
        "kind": "-",
        "target": "-",
        "ok": None,
    }
    report = case_dir / "report.json"
    if report.is_file():
        try:
            data = json.loads(_read_text(report))
            info["kind"] = data.get("kind", "-")
            info["target"] = data.get("target", "-")
        except Exception:  # noqa: BLE001
            pass
    if info["kind"] == "-":
        batch = case_dir / "batch.json"
        if batch.is_file():
            try:
                data = json.loads(_read_text(batch))
                info["kind"] = f"batch-{data.get('kind', '?')}"
                info["target"] = f"{len(data.get('rows') or [])} 个目标"
            except Exception:  # noqa: BLE001
                pass
    rows = _verify_manifest(case_dir)
    info["ok"] = all(r["ok"] for r in rows) if rows else None
    return info


def list_cases(limit: int | None = None, archived: bool = False) -> list[dict]:
    base = CASES_DIR / ARCHIVE_DIRNAME if archived else CASES_DIR
    items: list[dict] = []
    if not base.is_dir():
        return items
    dirs = sorted(
        (p for p in base.iterdir() if p.is_dir() and not p.name.startswith(".")),
        key=lambda p: p.name,
        reverse=True,
    )
    for d in dirs:
        items.append(_case_info(d))
        if limit and len(items) >= limit:
            break
    return items


def _case_dir(name: str) -> Path:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise HTTPException(status_code=400, detail="非法案件名")
    case_dir = CASES_DIR / name
    if not case_dir.is_dir():
        raise HTTPException(status_code=404, detail="案件不存在")
    return case_dir


# ---------------- 知识库 ----------------

def _kb_files() -> list[tuple[Path, Path]]:
    """列出 kb 下的 Markdown 文件（跳过隐藏目录，如 .vendor 素材库）。"""
    if not KB_ROOT.is_dir():
        return []
    files = []
    for path in sorted(KB_ROOT.rglob("*.md")):
        rel = path.relative_to(KB_ROOT)
        if any(part.startswith(".") for part in rel.parts):
            continue
        files.append((path, rel))
    return files


def _kb_list() -> dict:
    groups: dict[str, list] = {}
    for _, rel in _kb_files():
        top = "/".join(rel.parts[:-1]) if len(rel.parts) >= 2 else "(根目录)"
        groups.setdefault(top, []).append(
            {"name": rel.name, "rel": (Path("kb") / rel).as_posix()}
        )
    return groups


def _kb_search(q: str) -> list[dict]:
    ql = q.lower()
    results: list[dict] = []
    for path, rel in _kb_files():
        try:
            text = _read_text(path)
        except Exception:
            continue
        low = text.lower()
        if ql in path.name.lower() or ql in low:
            title = path.stem
            for line in text.splitlines():
                if line.strip().startswith("#"):
                    title = line.lstrip("# ").strip() or title
                    break
            index = low.find(ql)
            snippet = ""
            if index >= 0:
                snippet = text[max(0, index - 90): index + 160].replace("\n", " ")
            results.append(
                {
                    "rel": (Path("kb") / rel).as_posix(),
                    "title": title,
                    "snippet": snippet.strip(),
                }
            )
            if len(results) >= 60:
                break
    return results


def _kb_resolve(path: str) -> Path:
    resolved = (ROOT / path).resolve()
    if not resolved.is_relative_to(KB_ROOT.resolve()):
        raise HTTPException(status_code=404, detail="文件不存在")
    if not resolved.is_file() or resolved.suffix.lower() != ".md":
        raise HTTPException(status_code=404, detail="文件不存在")
    return resolved


# ---------------- 体检 ----------------

def _latest_baseline_raw() -> tuple[dict | None, str, str]:
    """最近基线 (data, 文件名, SHA-256)。无基线/解析失败时 data=None。"""
    if not OUT_DIR.is_dir():
        return None, "", ""
    files = sorted(OUT_DIR.glob("baseline-*.json"))
    if not files:
        return None, "", ""
    path = files[-1]
    try:
        data = json.loads(_read_text(path))
    except Exception:  # noqa: BLE001
        return None, path.name, ""
    return data, path.name, hashlib.sha256(path.read_bytes()).hexdigest()


def _latest_baseline() -> dict | None:
    if not OUT_DIR.is_dir():
        return None
    files = sorted(OUT_DIR.glob("baseline-*.json"))
    if not files:
        return None
    path = files[-1]
    empty = {
        "file": path.name, "capturedAt": None, "hosts": 0, "certs": 0, "ports": 0,
        "tasks": 0, "av": [], "rdp": "?", "smb1": "?", "firewall": [], "llmnr": "?",
        "netbios_on": 0, "netbios_total": 0, "hosts_other": [], "autoruns": 0, "issues": [],
    }
    try:
        data = json.loads(_read_text(path))
    except Exception:
        return empty
    return {
        "file": path.name,
        "capturedAt": data.get("capturedAt"),
        "hosts": len(data.get("hosts") or []),
        "certs": len(data.get("certs") or []),
        "ports": len(data.get("ports") or []),
        "tasks": len(data.get("tasks") or []),
        "av": data.get("av") or [],
        "rdp": (data.get("rdp") or ["?"])[0],
        "smb1": (data.get("smb1") or ["?"])[0],
        "firewall": data.get("firewall") or [],
        "llmnr": (data.get("llmnr") or ["?"])[0],
        "netbios_on": sum(1 for item in (data.get("netbios") or []) if str(item).endswith("=0")),
        "netbios_total": len(data.get("netbios") or []),
        "hosts_other": data.get("hostsOther") or [],
        "autoruns": len(data.get("autoruns") or []),
        "issues": baseline_issues(data),
    }


# ---------------- 路由 ----------------

@app.get("/", response_class=HTMLResponse)
def home(guard: str = ""):
    cases = list_cases()
    open_findings = [f for f in FINDINGS.list() if f.get("status") != "closed"]
    alerts = [f for f in open_findings if f.get("severity") in ("medium", "high", "critical")]
    digest_when = ""
    digest_path = OUT_DIR / "digest-latest.json"
    if digest_path.is_file():
        try:
            digest_when = str(json.loads(_read_text(digest_path)).get("when", ""))
        except Exception:  # noqa: BLE001
            pass
    bl_stats = BLOCKLIST.stats()
    stale_days = None
    for row in bl_stats:
        if row.get("downloaded") and row.get("updated"):
            try:
                when = datetime.strptime(row["updated"], "%Y-%m-%d %H:%M:%S")
                days = (datetime.now() - when).days
                stale_days = days if stale_days is None else min(stale_days, days)
            except Exception:  # noqa: BLE001
                pass
    return render(
        "dashboard.html",
        active="home",
        cases=cases[:6],
        case_count=len(cases),
        baseline=_latest_baseline(),
        guard=guard,
        kb_groups=_kb_list(),
        findings=FINDINGS.stats(),
        asset_count=len(ASSETS.list()),
        alerts=alerts[:3],
        alert_count=len(alerts),
        blocklist=bl_stats,
        stale_days=stale_days,
        health=load_health(OUT_DIR / "sources-health.json"),
        digest_when=digest_when,
        tasks_recent=TASKS.list()[:4],
        monitor=_monitor_cfg,
        ai_ready=ai_available(),
    )


@app.get("/triage", response_class=HTMLResponse)
def triage_page():
    return render("triage.html", active="triage")


@app.post("/triage/{kind}", response_class=HTMLResponse)
def triage_run(
    kind: str,
    target: str = Form(...),
    only: str = Form(""),
    no_save: str | None = Form(None),
    platforms: str | None = Form(None),
):
    kind = kind.lower()
    if kind not in _TRY_KINDS:
        raise HTTPException(status_code=404)
    target = target.strip()
    if not target:
        return RedirectResponse("/triage", status_code=303)

    client = _client()
    if kind == "phone":
        report = phone_mod.triage(target, client=client)
    elif kind == "ip":
        report = ip_mod.triage(target, client, blocklist=BLOCKLIST)
    elif kind == "user":
        if not user_mod.handle_ok(target):
            return render(
                "result.html",
                active="triage",
                error="用户名格式不合法：不支持空格、斜杠等特殊字符（支持中文），最长 64 位。",
                r=None,
                case_dir=None,
            )
        only_list = [s.strip() for s in only.split(",") if s.strip()] or None
        report = user_mod.triage(target, client, PLATFORMS, only=only_list)
    elif kind == "domain":
        report = domain_mod.triage(target, client)
    elif kind == "url":
        report = url_mod.triage(target, client)
    elif kind == "breach":
        report = breach_mod.triage(target, client)
    elif kind == "mailbox":
        report = mailbox_mod.triage(
            target,
            client,
            platforms_path=PLATFORMS if platforms == "on" else None,
        )
    else:
        report = email_mod.triage(target, client)

    case_dir = None
    if no_save != "on":
        case_dir = save_case(report, CASES_DIR)
    return render(
        "result.html",
        active="triage",
        error=None,
        r=_report_ctx(report),
        case_dir=str(case_dir) if case_dir else None,
        case_name=case_dir.name if case_dir else None,
        search_links=build_search_links(report.kind, report.target),
        ai_text=None,
        ai_error=None,
    )


@app.post("/ai/explain", response_class=HTMLResponse)
def triage_ai(case: str = Form(...)):
    case_dir = _case_dir(case)
    report_json = case_dir / "report.json"
    if not report_json.is_file():
        raise HTTPException(status_code=404, detail="案件缺少 report.json")
    try:
        data = json.loads(_read_text(report_json))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"report.json 解析失败: {exc}")
    ai_text = None
    ai_error = None
    if not ai_available():
        ai_error = "未配置 AI：请在 config/config.yaml 的 ai.api_key 填入密钥。"
    else:
        try:
            ai_text = summarize_report(data)
        except AIError as exc:
            ai_error = str(exc)
        except Exception as exc:  # noqa: BLE001
            ai_error = f"AI 调用失败：{type(exc).__name__}: {exc}"
    return render(
        "result.html",
        active="triage",
        error=None,
        r=_report_ctx_dict(data),
        case_dir=str(case_dir),
        case_name=case_dir.name,
        search_links=build_search_links(str(data.get("kind", "")), str(data.get("target", ""))),
        ai_text=ai_text,
        ai_error=ai_error,
    )


@app.get("/kb", response_class=HTMLResponse)
def kb_page(q: str = ""):
    q = q.strip()
    results = _kb_search(q) if q else []
    return render(
        "kb.html",
        active="kb",
        q=q,
        results=results,
        groups=_kb_list() if not q else {},
    )


@app.get("/kb/view", response_class=HTMLResponse)
def kb_view(path: str):
    resolved = _kb_resolve(path)
    text = _read_text(resolved)
    title = None
    for line in text.splitlines():
        if line.strip().startswith("#"):
            title = line.lstrip("# ").strip()
            break
    rel = (Path("kb") / resolved.relative_to(KB_ROOT.resolve())).as_posix()
    return render("kb_view.html", active="kb", body=_md(text), rel=rel, title=title or rel)


def _load_toolbox() -> dict:
    path = KB_ROOT / "tools" / "toolbox.yaml"
    if not path.is_file():
        return {}
    try:
        data = yaml.safe_load(_read_text(path)) or {}
    except Exception:  # noqa: BLE001
        return {}
    groups: dict[str, list] = {}
    for tool in data.get("tools", []):
        groups.setdefault(str(tool.get("category", "其他")), []).append(tool)
    return groups


@app.get("/tools", response_class=HTMLResponse)
def tools_page():
    catalog = KB_ROOT / "tools" / "catalog.md"
    body = _md(_read_text(catalog)) if catalog.is_file() else "<p>还没有工具目录。</p>"
    others: list[dict] = []
    tools_dir = KB_ROOT / "tools"
    if tools_dir.is_dir():
        others = [
            {"name": p.name, "rel": (Path("kb") / p.relative_to(KB_ROOT)).as_posix()}
            for p in sorted(tools_dir.glob("*.md"))
            if p.name != "catalog.md"
        ]
    return render("tools.html", active="tools", body=body, others=others, tool_groups=_load_toolbox())


@app.get("/cases", response_class=HTMLResponse)
def cases_page(q: str = "", kind: str = "", msg: str = ""):
    all_cases = list_cases()
    kind_cases = filter_cases(all_cases, "", kind)
    q = q.strip()
    meta_names: set[str] = set()
    content_hits: dict[str, str] = {}
    if q:
        meta_names = {c["name"] for c in filter_cases(kind_cases, q)}
        content_hits = {h["name"]: h["snippet"] for h in grep_cases(CASES_DIR, kind_cases, q)}
    selected = [c for c in kind_cases if not q or c["name"] in meta_names or c["name"] in content_hits]
    rows = []
    for case in selected[:200]:
        row = dict(case)
        if q and case["name"] in content_hits:
            row["snippet"] = content_hits[case["name"]]
        rows.append(row)
    kinds = sorted({str(c.get("kind") or "-") for c in all_cases})
    return render(
        "cases.html",
        active="cases",
        cases=rows,
        total=len(selected),
        content_count=sum(1 for row in rows if row.get("snippet")),
        all_count=len(all_cases),
        q=q,
        kind=kind,
        kinds=kinds,
        archived_count=len(list_cases(archived=True)),
        msg=msg,
    )


@app.get("/cases/archived", response_class=HTMLResponse)
def cases_archived(msg: str = ""):
    return render("archived.html", active="cases", cases=list_cases(archived=True), msg=msg)


@app.post("/cases/manage")
def cases_manage(names: list[str] = Form(default=[]), action: str = Form("archive")):
    if action == "archive":
        result = archive_cases(CASES_DIR, names)
        message = f"已归档 {len(result['archived'])} 个" + (
            f"，跳过 {len(result['skipped'])} 个" if result["skipped"] else ""
        )
    else:
        message = f"未知操作：{action}"
    return RedirectResponse(f"/cases?msg={quote(message)}", status_code=303)


@app.post("/cases/restore")
def cases_restore(names: list[str] = Form(default=[])):
    result = restore_cases(CASES_DIR, names)
    message = f"已恢复 {len(result['restored'])} 个" + (
        f"，跳过 {len(result['skipped'])} 个" if result["skipped"] else ""
    )
    return RedirectResponse(f"/cases/archived?msg={quote(message)}", status_code=303)


@app.post("/cases/delete")
def cases_delete(names: list[str] = Form(default=[]), confirm: str = Form("")):
    if confirm != "DELETE":
        message = "未删除：需要勾选「确认删除不可恢复」"
    else:
        result = delete_archived(CASES_DIR, names, confirm="DELETE")
        message = f"已永久删除 {len(result['deleted'])} 个" + (
            f"，跳过 {len(result['skipped'])} 个" if result["skipped"] else ""
        )
    return RedirectResponse(f"/cases/archived?msg={quote(message)}", status_code=303)


@app.get("/posture", response_class=HTMLResponse)
def posture_page():
    files = sorted(OUT_DIR.glob("baseline-*.json"))
    if not files:
        return render("posture.html", active="posture", name=None, data=None, diff=None, prev_name=None, issues=[], stats={})

    def _load(path: Path) -> dict:
        try:
            return json.loads(_read_text(path))
        except Exception:  # noqa: BLE001
            return {}

    latest_path = files[-1]
    data = _load(latest_path)
    prev_path = files[-2] if len(files) > 1 else None
    prev = _load(prev_path) if prev_path else None
    netbios = [str(x) for x in (data.get("netbios") or [])]
    stats = {
        "rdp": (data.get("rdp") or ["?"])[0],
        "smb1": (data.get("smb1") or ["?"])[0],
        "llmnr": (data.get("llmnr") or ["?"])[0],
        "netbios_on": sum(1 for item in netbios if item.endswith("=0")),
        "netbios_total": len(netbios),
        "proxy": (data.get("proxy") or ["?"])[0],
    }
    return render(
        "posture.html",
        active="posture",
        name=latest_path.name,
        data=data,
        diff=diff_baselines(prev, data) if prev is not None else None,
        prev_name=prev_path.name if prev_path else None,
        issues=baseline_issues(data),
        stats=stats,
    )


@app.get("/posture/export")
def posture_export(file: str = ""):
    files = sorted(OUT_DIR.glob("baseline-*.json"))
    if not files:
        raise HTTPException(status_code=404, detail="没有基线文件")
    if file:
        target = OUT_DIR / Path(file).name  # 只取文件名，防目录穿越
        if not target.is_file():
            raise HTTPException(status_code=404, detail="基线文件不存在")
    else:
        target = files[-1]
    return Response(
        content=target.read_bytes(),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(target.name)},
    )


@app.get("/cases/view", response_class=HTMLResponse)
def case_view(name: str):
    case_dir = _case_dir(name)
    rows = _verify_manifest(case_dir)
    report_md = case_dir / "report.md"
    body = _md(_read_text(report_md)) if report_md.is_file() else "<p>(缺少 report.md)</p>"
    return render(
        "case_view.html",
        active="cases",
        name=name,
        rows=rows,
        body=body,
        all_ok=all(r["ok"] for r in rows) if rows else None,
        severities=SEVERITIES,
    )


@app.get("/cases/export")
def case_export(name: str, format: str = "html", template: str = "standard"):
    case_dir = _case_dir(name)
    fmt = (format or "html").lower()
    try:
        filename, content = export_case(case_dir, fmt, template=template)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(exc))
    media = "text/markdown; charset=utf-8" if fmt == "md" else "text/html; charset=utf-8"
    disposition = "attachment; filename*=UTF-8''" + quote(filename)
    return Response(content=content, media_type=media, headers={"Content-Disposition": disposition})


def _pack_response(names: list[str], template: str) -> Response:
    try:
        filename, content = build_package(CASES_DIR, names, template)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return Response(
        content=content,
        media_type="application/zip",
        headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(filename)},
    )


@app.get("/cases/pack")
def cases_pack(names: list[str] = Query(default=[]), template: str = "standard"):
    return _pack_response(names, template)


@app.post("/cases/pack")
def cases_pack_post(names: list[str] = Form(default=[]), template: str = Form("standard")):
    return _pack_response(names, template)


@app.get("/tasks", response_class=HTMLResponse)
def tasks_page(error: str = ""):
    return render("tasks.html", active="tasks", tasks=TASKS.list(), error=error)


@app.post("/tasks/patrol")
def tasks_patrol(
    kind: str = Form(""),
    target: str = Form(""),
    posture: str | None = Form(None),
    ai: str | None = Form(None),
):
    has_posture = posture == "on"
    has_ai = ai == "on"
    kind = kind.strip()
    target = target.strip()
    if not has_posture and not (kind and target):
        return RedirectResponse("/tasks?error=empty", status_code=303)
    if kind and kind not in {"phone", "ip", "user", "domain", "url"}:
        raise HTTPException(status_code=400, detail="未知研判类型")
    title_parts = []
    if has_posture:
        title_parts.append("体检")
    if kind and target:
        title_parts.append(f"研判:{kind}:{target}")
    if has_ai:
        title_parts.append("AI")
    TASKS.submit(
        "patrol",
        "一键巡检（" + " + ".join(title_parts) + "）",
        {"kind": kind, "target": target, "posture": has_posture, "ai": has_ai},
    )
    return RedirectResponse("/tasks", status_code=303)


@app.get("/api/tasks")
def api_tasks():
    return JSONResponse(TASKS.list())


@app.get("/findings", response_class=HTMLResponse)
def findings_page(status: str = "", severity: str = ""):
    return render(
        "findings.html",
        active="findings",
        findings=FINDINGS.list(status=status or None, severity=severity or None),
        filter_status=status,
        filter_severity=severity,
        severities=SEVERITIES,
        statuses=STATUSES,
        imported=None,
        skipped=None,
        import_error=None,
    )


@app.post("/findings/new")
def findings_new(
    title: str = Form(...),
    severity: str = Form("info"),
    detail: str = Form(""),
    case: str = Form(""),
    asset_value: str = Form(""),
    asset_type: str = Form(""),
):
    case = case.strip() or None
    asset_value = asset_value.strip()
    asset_id = None
    if case and not asset_value:
        report_json = CASES_DIR / case / "report.json"
        if report_json.is_file():
            try:
                data = json.loads(_read_text(report_json))
                kind = str(data.get("kind") or "")
                target = str(data.get("target") or "")
                if target and kind in ("ip", "phone", "username"):
                    asset = ASSETS.upsert(kind_to_type(kind), target, case=case)
                    asset_id = asset["id"]
            except Exception:  # noqa: BLE001
                pass
    elif asset_value:
        asset = ASSETS.upsert(asset_type, asset_value, case=case)
        asset_id = asset["id"]
    finding = FINDINGS.create(title, severity=severity, detail=detail, source="manual", case=case, asset=asset_id)
    if severity in ("high", "critical"):
        notify_finding(finding)
    return RedirectResponse("/findings", status_code=303)


@app.post("/findings/status")
def findings_status(fid: str = Form(...), status: str = Form(...), note: str = Form("")):
    FINDINGS.set_status(fid, status, note=note or None)
    return RedirectResponse("/findings", status_code=303)


@app.post("/findings/note")
def findings_note(fid: str = Form(...), text: str = Form(...)):
    FINDINGS.add_note(fid, text)
    return RedirectResponse("/findings", status_code=303)


@app.post("/findings/import", response_class=HTMLResponse)
def findings_import(path: str = Form(...), format: str = Form("auto")):
    file_path = Path(path.strip())
    if not file_path.is_absolute():
        file_path = ROOT / file_path

    def _back(imported=None, skipped=None, import_error=None):
        return render(
            "findings.html",
            active="findings",
            findings=FINDINGS.list(),
            filter_status="",
            filter_severity="",
            severities=SEVERITIES,
            statuses=STATUSES,
            imported=imported,
            skipped=skipped,
            import_error=import_error,
        )

    if not file_path.is_file():
        return _back(import_error=f"文件不存在：{file_path}")
    try:
        stats = import_file(file_path, format, FINDINGS, ASSETS)
    except Exception as exc:  # noqa: BLE001
        return _back(import_error=f"导入失败：{type(exc).__name__}: {exc}")
    return _back(imported=stats["imported"], skipped=stats["skipped"])


@app.get("/api/findings")
def api_findings(status: str = "", severity: str = ""):
    return JSONResponse(FINDINGS.list(status=status or None, severity=severity or None))


@app.get("/assets", response_class=HTMLResponse)
def assets_page(type: str = ""):
    return render(
        "assets.html",
        active="assets",
        assets=ASSETS.list(type_=type or None),
        filter_type=type,
        types=ASSET_TYPES,
    )


@app.post("/assets/new")
def assets_new(
    type: str = Form(...),
    value: str = Form(...),
    label: str = Form(""),
    tags: str = Form(""),
    note: str = Form(""),
):
    tag_list = [t.strip() for t in tags.split(",") if t.strip()]
    ASSETS.upsert(type, value, label=label, tags=tag_list, note=note)
    return RedirectResponse("/assets", status_code=303)


@app.get("/assets/view", response_class=HTMLResponse)
def asset_view(id: str):
    asset = ASSETS.get(id)
    if not asset:
        raise HTTPException(status_code=404, detail="资产不存在")
    return render(
        "asset_view.html",
        active="assets",
        asset=asset,
        findings=FINDINGS.list_by_asset(id),
        severities=SEVERITIES,
    )


@app.get("/api/assets")
def api_assets(type: str = ""):
    return JSONResponse(ASSETS.list(type_=type or None))


@app.post("/guard/run")
def guard_run():
    if not POSTURE_SCRIPT.is_file():
        return RedirectResponse("/?guard=missing", status_code=303)
    try:
        subprocess.Popen(
            [
                "pwsh",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(POSTURE_SCRIPT),
                "-Baseline",
            ],
            cwd=str(ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return RedirectResponse("/?guard=error", status_code=303)
    return RedirectResponse("/?guard=started", status_code=303)


# ---------------- 封堵清单 ----------------

@app.get("/blocklist", response_class=HTMLResponse)
def blocklist_page(updated: str = "", checked: str = ""):
    hits = None
    check_error = None
    if checked:
        try:
            hits = BLOCKLIST.check_ip(checked)
        except Exception as exc:  # noqa: BLE001
            check_error = str(exc)
    stats = BLOCKLIST.stats()
    return render(
        "blocklist.html",
        active="blocklist",
        stats=stats,
        total=sum(int(s.get("count") or 0) for s in stats),
        custom=BLOCKLIST.custom_list(),
        updated=updated,
        checked=checked,
        hits=hits,
        check_error=check_error,
    )


@app.post("/blocklist/custom/add")
def blocklist_custom_add(value: str = Form(...)):
    ok, message = BLOCKLIST.add_custom(value)
    return RedirectResponse(f"/blocklist?updated={quote(message)}", status_code=303)


@app.post("/blocklist/custom/remove")
def blocklist_custom_remove(value: str = Form(...)):
    removed = BLOCKLIST.remove_custom(value)
    message = f"已移除 {value.strip()}" if removed else f"未找到 {value.strip()}"
    return RedirectResponse(f"/blocklist?updated={quote(message)}", status_code=303)


@app.post("/blocklist/update")
def blocklist_update():
    results = BLOCKLIST.update(_client())
    summary = "；".join(
        f"{key}: " + (f"OK（{value.get('count')} 条）" if value.get("ok") else f"FAIL（{value.get('error', '')[:60]}）")
        for key, value in results.items()
    )
    return RedirectResponse(f"/blocklist?updated={quote(summary)}", status_code=303)


@app.post("/blocklist/check")
def blocklist_check(ip: str = Form(...)):
    return RedirectResponse(f"/blocklist?checked={quote(ip.strip())}", status_code=303)


@app.get("/blocklist/export")
def blocklist_export(kind: str = "ps1"):
    if kind == "csv":
        content = BLOCKLIST.export_csv()
        media = "text/csv; charset=utf-8"
        name = "sentinel-blocklist.csv"
    else:
        content = BLOCKLIST.export_firewall_script()
        media = "text/plain; charset=utf-8"
        name = "sentinel-firewall-block.ps1"
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote(name)},
    )


# ---------------- 主机加固 ----------------

@app.get("/hardening", response_class=HTMLResponse)
def hardening_page():
    data, name, _ = _latest_baseline_raw()
    context = {
        "active": "hardening",
        "baseline_name": name or None,
        "actions": hardening.available_actions(data) if data else [],
    }
    return render("hardening.html", **context)


@app.get("/hardening/script")
def hardening_script():
    data, name, sha = _latest_baseline_raw()
    if data is None:
        raise HTTPException(status_code=404, detail="还没有可用的体检基线：请先在总览页运行「立即跑一次体检」")
    content = hardening.build_script(data, baseline_name=name, baseline_sha=sha)
    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": "attachment; filename*=UTF-8''" + quote("sentinel-hardening.ps1")},
    )


# ---------------- 批量研判 ----------------

@app.get("/batch", response_class=HTMLResponse)
def batch_page(error: str = ""):
    return render("batch.html", active="batch", kinds=BATCH_KINDS, error=error)


@app.post("/batch")
def batch_submit(kind: str = Form(...), targets: str = Form(...)):
    kind = kind.strip().lower()
    items = parse_targets(targets)
    if kind not in BATCH_KINDS or not items:
        return RedirectResponse("/batch?error=empty", status_code=303)
    TASKS.submit("batch", f"批量研判（{kind}，{len(items)} 项）", {"kind": kind, "targets": items})
    return RedirectResponse("/tasks", status_code=303)


# ---------------- 数据源健康 ----------------

@app.get("/sources", response_class=HTMLResponse)
def sources_page(started: str = ""):
    health = load_health(OUT_DIR / "sources-health.json")
    running = any(
        t.get("kind") == "sources" and t.get("status") in ("queued", "running") for t in TASKS.list()
    )
    return render("sources.html", active="sources", health=health, started=started, running=running)


@app.post("/sources/run")
def sources_run():
    if any(
        t.get("kind") == "sources" and t.get("status") in ("queued", "running") for t in TASKS.list()
    ):
        return RedirectResponse("/sources?started=2", status_code=303)
    TASKS.submit("sources", "数据源健康检测", {})
    return RedirectResponse("/sources?started=1", status_code=303)


# ---------------- 每日摘要 ----------------

@app.get("/digest", response_class=HTMLResponse)
def digest_page(started: str = ""):
    from ..core.digest import render_text

    digest = None
    text = ""
    path = OUT_DIR / "digest-latest.json"
    if path.is_file():
        try:
            digest = json.loads(_read_text(path))
            text = render_text(digest)
        except Exception:  # noqa: BLE001
            digest = None
    running = any(
        t.get("kind") == "digest" and t.get("status") in ("queued", "running") for t in TASKS.list()
    )
    return render("digest.html", active="digest", digest=digest, digest_text=text, started=started, running=running)


@app.post("/digest/run")
def digest_run():
    TASKS.submit("digest", "每日摘要", {})
    return RedirectResponse("/digest?started=1", status_code=303)


def main() -> None:
    parser = argparse.ArgumentParser(prog="sentinel-web", description="Sentinel 本地工作台")
    parser.add_argument("--host", default="127.0.0.1", help="默认仅本机访问")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    inject_os_truststore()
    import uvicorn

    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
