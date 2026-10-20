"""案件报告导出：标准 / 简报 / 证据版（自包含 HTML，可打印为 PDF）+ Markdown。"""

from __future__ import annotations

import hashlib
import html as html_lib
import json
from datetime import datetime
from pathlib import Path
from string import Template

from .. import __version__
from .config import load_config

_PAGE = Template(
    """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>$title</title>
<style>
  body { font: 14px/1.7 "Segoe UI","Microsoft YaHei",system-ui,sans-serif; color: #1a1d23; margin: 28px auto; max-width: 880px; padding: 0 20px; }
  h1 { font-size: 22px; border-bottom: 2px solid #2b6cb0; padding-bottom: 8px; }
  h2 { font-size: 16px; margin-top: 26px; border-left: 4px solid #2b6cb0; padding-left: 8px; }
  table { width: 100%; border-collapse: collapse; margin: 10px 0 18px; }
  th, td { border: 1px solid #d0d7de; padding: 6px 10px; text-align: left; vertical-align: top; font-size: 13px; }
  th { background: #f6f8fa; }
  .meta { color: #57606a; font-size: 13px; }
  .badge { display: inline-block; padding: 1px 8px; border-radius: 10px; font-size: 12px; border: 1px solid #d0d7de; color: #57606a; }
  .ok { color: #1a7f37; border-color: #1a7f37; }
  .bad { color: #cf222e; border-color: #cf222e; }
  .foot { margin-top: 34px; border-top: 1px solid #d0d7de; padding-top: 10px; color: #57606a; font-size: 12px; }
  .mono { font-family: Consolas, monospace; font-size: 12px; }
  .no-print { margin: 0 0 18px; }
  .no-print button { padding: 8px 16px; border-radius: 8px; border: 1px solid #2b6cb0; background: #2b6cb0; color: #fff; cursor: pointer; font-size: 14px; }
  @page { margin: 18mm; }
  @media print { .no-print { display: none; } body { margin: 0; } a { color: inherit; text-decoration: none; } }
</style>
</head>
<body>
$print_bar
<h1>安全研判报告$template_label</h1>
<p class="meta">报告编号：<span class="mono">$case_name</span>$issuer</p>
<p class="meta">类型：$kind ｜ 目标：<span class="mono">$target</span> ｜ 研判时间：$created ｜ 导出时间：$exported ｜ 工具：Sentinel v$version</p>
$sections
<div class="foot">
  <p>本报告仅基于公开数据源与本地离线解析生成，用于防御建设与合法维权取证。</p>
  <p>证据清单（SHA-256）用于核验材料完整性；请勿将本报告用于未经授权的场景。</p>
</div>
</body>
</html>
"""
)

_TEMPLATE_LABELS = {"standard": "", "brief": "（简报）", "evidence": "（证据版）"}
_CONF_CLASS = {"confirmed": "ok", "likely": "ok", "unverified": "", "unavailable": "bad"}


def _esc(value) -> str:
    return html_lib.escape(str(value), quote=True)


def _ai_div(text: str) -> str:
    body = _esc(text).replace("\n", "<br>")
    return (
        "<div style='white-space:pre-wrap; background:#f6f8fa; padding:12px; border-radius:8px; font-size:13px;'>"
        + body
        + "</div>"
    )


def _findings_table(findings: list[dict], limit: int | None = None) -> str:
    rows_src = findings[: limit or len(findings)]
    rows = []
    for item in rows_src:
        cls = _CONF_CLASS.get(str(item.get("confidence", "")), "")
        rows.append(
            "<tr><td>{}</td><td>{}</td><td><span class='badge {}'>{}</span></td><td>{}</td></tr>".format(
                _esc(item.get("key")), _esc(item.get("value")), cls,
                _esc(item.get("confidence")), _esc(item.get("source")),
            )
        )
    table = (
        "<table><thead><tr><th>字段</th><th>值</th><th>置信度</th><th>来源</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    ) if rows else "<p class='meta'>（无）</p>"
    if limit and len(findings) > limit:
        table += f"<p class='meta'>…… 其余 {len(findings) - limit} 条见标准版报告</p>"
    return table


def _sources_table(sources: list[dict]) -> str:
    rows = []
    for item in sources:
        status = "<span class='badge ok'>OK</span>" if item.get("ok") else "<span class='badge bad'>FAIL</span>"
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _esc(item.get("source")), status, _esc(item.get("detail") or item.get("error"))
            )
        )
    return (
        "<table><thead><tr><th>数据源</th><th>状态</th><th>说明</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    ) if rows else "<p class='meta'>（无）</p>"


def _notes_list(notes: list[str]) -> str:
    if not notes:
        return "<p class='meta'>（无）</p>"
    return "<ul>" + "".join(f"<li>{_esc(n)}</li>" for n in notes) + "</ul>"


def _evidence_rows(case_dir: Path) -> list[tuple[str, str, bool]]:
    manifest = case_dir / "manifest.json"
    if not manifest.is_file():
        return []
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return []
    rows = []
    for item in data.get("files", []):
        path = case_dir / str(item.get("path", ""))
        ok = path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == item.get("sha256")
        rows.append((str(item.get("path")), str(item.get("sha256")), ok))
    return rows


def _evidence_table(case_dir: Path, simple: bool = False) -> str:
    rows = _evidence_rows(case_dir)
    if not rows:
        return "<p class='meta'>（无 manifest.json）</p>"
    html_rows = []
    for name, digest, ok in rows:
        status = "<span class='badge ok'>校验通过</span>" if ok else "<span class='badge bad'>校验失败</span>"
        if simple:
            html_rows.append(f"<tr><td class='mono'>{_esc(name)}</td><td>{status}</td></tr>")
        else:
            html_rows.append(
                f"<tr><td class='mono'>{_esc(name)}</td><td class='mono'>{_esc(digest)}</td><td>{status}</td></tr>"
            )
    head = "<th>文件</th><th>校验</th>" if simple else "<th>文件</th><th>SHA-256</th><th>校验</th>"
    return f"<table><thead><tr>{head}</tr></thead><tbody>{''.join(html_rows)}</tbody></table>"


def _brief_summary(data: dict, findings: list[dict]) -> str:
    if data.get("ai"):
        return "<h2>摘要</h2>" + _ai_div(data["ai"])
    counts: dict[str, int] = {}
    for item in findings:
        key = str(item.get("confidence", "unverified"))
        counts[key] = counts.get(key, 0) + 1
    parts = "、".join(f"{k} {v}" for k, v in counts.items()) or "无结论字段"
    notes = len(data.get("notes") or [])
    return f"<h2>摘要</h2><p>本报告共 {len(findings)} 条结论（{_esc(parts)}），备注 {notes} 条。详细数据源与完整证据见标准版。</p>"


def export_case(case_dir: Path, fmt: str = "html", template: str = "standard") -> tuple[str, str]:
    """导出案件，返回 (文件名, 内容)。fmt: html|md；template: standard|brief|evidence。"""
    case_dir = Path(case_dir)
    fmt = (fmt or "html").lower()
    template = (template or "standard").lower()
    if template not in _TEMPLATE_LABELS:
        template = "standard"

    if fmt == "md":
        report_md = case_dir / "report.md"
        if not report_md.is_file():
            raise FileNotFoundError(f"{case_dir.name}: 缺少 report.md")
        return f"{case_dir.name}-report.md", report_md.read_text(encoding="utf-8")

    if fmt != "html":
        raise ValueError(f"不支持的导出格式: {fmt}")

    report_json = case_dir / "report.json"
    data: dict = {}
    if report_json.is_file():
        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {}

    kind = str(data.get("kind", "-"))
    target = str(data.get("target", case_dir.name))
    created = str(data.get("created_at", "-"))
    findings = data.get("findings") or []

    sections: list[str] = []
    if template == "brief":
        sections.append(_brief_summary(data, findings))
        sections.append("<h2>关键字段（前 10 条）</h2>" + _findings_table(findings, limit=10))
        sections.append("<h2>证据清单（简）</h2>" + _evidence_table(case_dir, simple=True))
    elif template == "evidence":
        sections.append("<h2>结论字段</h2>" + _findings_table(findings))
        sections.append("<h2>证据清单（SHA-256，完整）</h2>" + _evidence_table(case_dir))
        if data.get("ai"):
            sections.append("<h2>AI 解读（自动生成）</h2>" + _ai_div(data["ai"]))
        sections.append("<h2>备注</h2>" + _notes_list(data.get("notes") or []))
    else:
        sections.append("<h2>结论字段</h2>" + _findings_table(findings))
        sections.append("<h2>数据源状态</h2>" + _sources_table(data.get("sources") or []))
        if data.get("ai"):
            sections.append("<h2>AI 解读（自动生成）</h2>" + _ai_div(data["ai"]))
        elif data.get("ai_error"):
            sections.append(f"<h2>AI 解读（自动生成）</h2><p class='meta'>（失败：{_esc(data['ai_error'])}）</p>")
        sections.append("<h2>证据清单（SHA-256）</h2>" + _evidence_table(case_dir))
        sections.append("<h2>备注</h2>" + _notes_list(data.get("notes") or []))

    issuer_cfg = load_config().get("report") or {}
    issuer = str(issuer_cfg.get("issuer") or "").strip()
    issuer_html = f" ｜ 出具：{_esc(issuer)}" if issuer else ""

    content = _PAGE.substitute(
        title=_esc(f"研判报告 {kind} {target}"),
        template_label=_TEMPLATE_LABELS[template],
        case_name=_esc(case_dir.name),
        issuer=issuer_html,
        kind=_esc(kind),
        target=_esc(target),
        created=_esc(created),
        exported=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        version=_esc(__version__),
        print_bar="<div class='no-print'><button onclick='window.print()'>打印 / 保存为 PDF</button></div>",
        sections="\n".join(sections),
    )
    suffix = "" if template == "standard" else f"-{template}"
    return f"{case_dir.name}-report{suffix}.html", content
