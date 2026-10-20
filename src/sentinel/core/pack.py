"""案件打包导出：多选案件 → 一个 zip（索引页 + 每案 HTML/Markdown/JSON/证据清单）。

用于交付场景：把一批研判卷宗一次打包给同事 / 交给维权流程；
包内每个案件同时保留原始 report.json 与 manifest.json（SHA-256 可复核）。
"""

from __future__ import annotations

import hashlib
import html as html_lib
import io
import json
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote

from .. import __version__
from .export import export_case

MAX_CASES = 100

_TEMPLATE_SUFFIX = {"standard": "", "brief": "-brief", "evidence": "-evidence"}


def _esc(value) -> str:
    return html_lib.escape(str(value), quote=True)


def integrity(case_dir: Path) -> tuple[bool | None, int, int]:
    """(全部通过?, 通过数, 总数)；无 manifest 时 (None, 0, 0)。"""
    manifest = case_dir / "manifest.json"
    if not manifest.is_file():
        return None, 0, 0
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None, 0, 0
    rows = data.get("files") or []
    if not rows:
        return None, 0, 0
    ok_count = 0
    for item in rows:
        path = case_dir / str(item.get("path", ""))
        if path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == item.get("sha256"):
            ok_count += 1
    return ok_count == len(rows), ok_count, len(rows)


def _index_html(rows: list[dict], exported: str, root: str) -> str:
    body_rows = []
    for row in rows:
        if row["integrity"] is None:
            badge = "<span class='badge'>-</span>"
        elif row["integrity"]:
            badge = "<span class='badge ok'>校验通过</span>"
        else:
            badge = f"<span class='badge bad'>{row['ok_count']}/{row['total']} 通过</span>"
        link = f"cases/{row['name']}/report.html"
        body_rows.append(
            "<tr><td class='mono'>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><a href=\"{}\">报告</a></td></tr>".format(
                _esc(row["name"]), _esc(row["kind"]), _esc(row["target"]), _esc(row["created"]), badge, _esc(link)
            )
        )
    return """<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Sentinel 案件包索引</title>
<style>
  body {{ font: 14px/1.7 "Segoe UI","Microsoft YaHei",system-ui,sans-serif; color:#1a1d23; margin:28px auto; max-width:1000px; padding:0 20px; }}
  h1 {{ font-size:22px; border-bottom:2px solid #2b6cb0; padding-bottom:8px; }}
  table {{ width:100%; border-collapse:collapse; margin:14px 0; }}
  th,td {{ border:1px solid #d0d7de; padding:6px 10px; text-align:left; font-size:13px; vertical-align:top; }}
  th {{ background:#f6f8fa; }}
  .meta {{ color:#57606a; font-size:13px; }}
  .badge {{ display:inline-block; padding:1px 8px; border-radius:10px; font-size:12px; border:1px solid #d0d7de; color:#57606a; }}
  .ok {{ color:#1a7f37; border-color:#1a7f37; }}
  .bad {{ color:#cf222e; border-color:#cf222e; }}
  .mono {{ font-family:Consolas,monospace; font-size:12px; }}
  .foot {{ margin-top:30px; border-top:1px solid #d0d7de; padding-top:10px; color:#57606a; font-size:12px; }}
</style></head><body>
<h1>Sentinel 案件包</h1>
<p class="meta">导出时间：{exported} ｜ 案件数：{count} ｜ 工具：Sentinel v{version} ｜ 包根目录：<span class="mono">{root}</span></p>
<table><thead><tr><th>案件</th><th>类型</th><th>目标</th><th>时间</th><th>证据清单</th><th></th></tr></thead>
<tbody>{rows}</tbody></table>
<div class="foot">
  <p>每个案件目录内含：report.html（可打印 PDF）、report.md、report.json（原始数据）、manifest.json（SHA-256 证据清单）。</p>
  <p>本包仅基于公开数据源与本地离线解析生成，用于防御建设与合法维权取证。</p>
</div></body></html>""".format(
        exported=_esc(exported), count=len(rows), version=_esc(__version__), root=_esc(root), rows="".join(body_rows)
    )


def build_package(cases_dir: Path, names: list[str] | None = None, template: str = "standard") -> tuple[str, bytes]:
    """生成案件 zip，返回 (文件名, 字节)。names 为空 → 打包全部（按时间倒序，上限 100）。"""
    cases_dir = Path(cases_dir)
    template = template if template in _TEMPLATE_SUFFIX else "standard"
    if not names:
        names = [
            d.name
            for d in sorted((p for p in cases_dir.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True)
        ]
    selected: list[Path] = []
    base = cases_dir.resolve()
    for name in list(names)[:MAX_CASES]:
        target = str(name).strip()
        if not target or "/" in target or "\\" in target or target.startswith("."):
            continue
        path = cases_dir / target
        if not path.is_dir():
            decoded = unquote(target)
            if decoded != target:
                path = cases_dir / decoded
        if not path.is_dir():
            continue
        try:
            if not path.resolve().is_relative_to(base):
                continue  # 解码后逃逸出案件目录的输入一律拒绝
        except OSError:
            continue
        selected.append(path)
    if not selected:
        raise ValueError("没有可打包的案件")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    root = f"sentinel-cases-{stamp}"
    exported = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    buffer = io.BytesIO()
    rows: list[dict] = []

    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for case_dir in selected:
            prefix = f"{root}/cases/{case_dir.name}/"
            for fname in ("report.md", "report.json", "manifest.json"):
                path = case_dir / fname
                if path.is_file():
                    archive.writestr(prefix + fname, path.read_bytes())
            html_inner = f"report{_TEMPLATE_SUFFIX[template]}.html"
            try:
                _, html_text = export_case(case_dir, "html", template=template)
                archive.writestr(prefix + html_inner, html_text)
            except Exception:  # noqa: BLE001
                html_inner = ""
            data: dict = {}
            report_json = case_dir / "report.json"
            if report_json.is_file():
                try:
                    data = json.loads(report_json.read_text(encoding="utf-8"))
                except Exception:  # noqa: BLE001
                    data = {}
            all_ok, ok_count, total = integrity(case_dir)
            rows.append({
                "name": case_dir.name,
                "kind": str(data.get("kind", "-")),
                "target": str(data.get("target", "-")),
                "created": str(data.get("created_at", "-")),
                "integrity": all_ok,
                "ok_count": ok_count,
                "total": total,
                "html": html_inner,
            })
        archive.writestr(f"{root}/index.html", _index_html(rows, exported, root))
        archive.writestr(
            f"{root}/README.txt",
            "Sentinel 案件包\n"
            f"导出时间: {exported}\n"
            f"案件数: {len(rows)}\n\n"
            "用法: 打开 index.html 浏览索引；每个案件目录内含 report.html（可打印 PDF）/ report.md /\n"
            "report.json（原始数据）/ manifest.json（SHA-256 证据清单）。\n"
            "校验: 对案件目录内文件重新计算 SHA-256，与 manifest.json 比对即可确认完整性。\n",
        )
    return f"{root}.zip", buffer.getvalue()
