"""批量研判：目标列表 → 逐条研判（自动落档）→ 聚合报告；风险项自动登记发现。

用于实战批量场景：从日志/告警里抄一列可疑 IP，或一批域名/号码，
一次性跑完并把明确的风险自动进「发现管理」。
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

from ..modules import domain as domain_mod
from ..modules import ip as ip_mod
from ..modules import mailbox as mailbox_mod
from ..modules import phone as phone_mod
from ..modules import url as url_mod
from ..modules import username as user_mod
from .assets import AssetStore, kind_to_type
from .case import save_case
from .findings import FindingStore
from .notify import notify_min_severity, notify_summary, severity_at_least

BATCH_KINDS = ("ip", "phone", "user", "domain", "url", "mailbox")
MAX_TARGETS = 200

_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def parse_targets(text: str) -> list[str]:
    """一行一个目标；去重、去注释（# 开头）、去空白；最多 200 条。"""
    seen: list[str] = []
    for line in (text or "").splitlines():
        item = line.strip()
        if not item or item.startswith("#"):
            continue
        if item not in seen:
            seen.append(item)
    return seen[:MAX_TARGETS]


def triage_one(kind: str, target: str, client, blocklist=None):
    if kind == "ip":
        return ip_mod.triage(target, client, blocklist=blocklist)
    if kind == "phone":
        return phone_mod.triage(target, client=client)
    if kind == "domain":
        return domain_mod.triage(target, client)
    if kind == "url":
        return url_mod.triage(target, client)
    if kind == "mailbox":
        return mailbox_mod.triage(target, client, skip_gravatar=True)
    if kind == "user":
        if not user_mod.handle_ok(target):
            raise ValueError("用户名格式不合法")
        platforms = Path(__file__).resolve().parents[1] / "data" / "platforms.yaml"
        return user_mod.triage(target, client, platforms)
    raise ValueError(f"不支持的批量类型: {kind}")


def assess_report(kind: str, data: dict) -> list[dict]:
    """从报告里提取"值得登记发现"的风险项（保守规则，宁缺勿假）。"""
    findings = {f.get("key", ""): str(f.get("value", "")) for f in data.get("findings") or []}
    out: list[dict] = []
    if kind == "ip":
        hit = findings.get("封堵清单命中", "")
        if hit and "未命中" not in hit:
            out.append({"severity": "high", "reason": f"命中封堵清单（{hit[:60]}）"})
        if findings.get("已知 CVE"):
            out.append({"severity": "medium", "reason": f"已知 CVE：{findings['已知 CVE'][:60]}"})
        for key, label in (("DShield 攻击记录", "DShield 攻击记录"), ("blocklist.de 举报/攻击", "blocklist.de 举报")):
            value = findings.get(key, "")
            nums = [int(n) for n in re.findall(r"\d+", value)]
            if nums and max(nums) > 0:
                out.append({"severity": "medium", "reason": f"{label}（{value[:50]}）"})
    elif kind == "url":
        risk = findings.get("风险特征", "")
        count = risk.count("⚠")
        if count >= 3:
            out.append({"severity": "medium", "reason": f"{count} 项风险特征"})
        elif count >= 1:
            out.append({"severity": "low", "reason": f"{count} 项风险特征"})
    elif kind == "domain":
        rating = findings.get("体检评级", "")
        if rating.startswith("D"):
            out.append({"severity": "medium", "reason": "域名体检评级 D"})
        elif rating.startswith("C"):
            out.append({"severity": "low", "reason": "域名体检评级 C"})
    elif kind == "mailbox":
        if "一次性" in findings.get("邮箱性质", ""):
            out.append({"severity": "low", "reason": "一次性邮箱（临时邮箱服务）"})
        if "NXDOMAIN" in findings.get("域名解析", ""):
            out.append({"severity": "low", "reason": "邮箱域不存在（地址无效）"})
    return out


def _summary_line(kind: str, data: dict) -> str:
    findings = {f.get("key", ""): str(f.get("value", "")) for f in data.get("findings") or []}
    if kind == "ip":
        bits = [findings.get("国家", ""), findings.get("ISP/机构", "")]
        threat = "有威胁情报命中" if any("封堵清单命中" in k and "未命中" not in v for k, v in findings.items()) else ""
        return " · ".join(x for x in bits + [threat] if x)
    if kind == "phone":
        return " · ".join(x for x in (findings.get("运营商", "") or findings.get("运营商(360)", ""),
                                      findings.get("归属地", "") or findings.get("归属地(360)", "")) if x)
    if kind == "user":
        return findings.get("探活统计", "")
    if kind == "domain":
        return findings.get("体检评级", "")
    if kind == "url":
        risk = findings.get("风险特征", "")
        return f"风险特征 {risk.count('⚠')} 项" if risk else ""
    if kind == "mailbox":
        return findings.get("邮箱画像", "") or findings.get("格式校验", "")
    return ""


def run_batch(
    kind: str,
    targets: list[str],
    client,
    cases_dir: Path,
    findings_store: FindingStore | None = None,
    assets_store: AssetStore | None = None,
    blocklist=None,
    log=print,
    save: bool = True,
) -> dict:
    if kind not in BATCH_KINDS:
        raise ValueError(f"不支持的批量类型: {kind}")
    cases_dir = Path(cases_dir)
    stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
    run_dir = cases_dir / f"{stamp}-batch-{kind}"
    run_dir.mkdir(parents=True, exist_ok=True)

    existing_titles = {f.get("title") for f in findings_store.list()} if findings_store else set()
    rows: list[dict] = []
    findings_created = 0
    risky = 0
    created_findings: list[dict] = []

    for index, target in enumerate(targets, start=1):
        log(f"[{index}/{len(targets)}] {kind} {target} …")
        row: dict = {"target": target, "case": None, "summary": "", "risks": []}
        try:
            report = triage_one(kind, target, client, blocklist=blocklist)
            case_dir = save_case(report, cases_dir) if save else None
            data = report.to_dict()
            risks = assess_report(kind, data)
            row["case"] = case_dir.name if case_dir else None
            row["risks"] = risks
            row["summary"] = _summary_line(kind, data)
            rows.append(row)
            if risks:
                risky += 1
                severity = max((r["severity"] for r in risks), key=_SEVERITY_ORDER.index)
                title = f"[批量] {kind} {target}：{risks[0]['reason']}"
                if findings_store and title not in existing_titles:
                    asset_id = None
                    if assets_store is not None:
                        asset = assets_store.upsert(kind_to_type(kind), target, case=row["case"])
                        asset_id = asset["id"]
                    finding = findings_store.create(
                        title,
                        severity=severity,
                        detail=json.dumps(data.get("findings") or [], ensure_ascii=False, indent=2),
                        source="batch",
                        case=row["case"],
                        asset=asset_id,
                    )
                    existing_titles.add(title)
                    findings_created += 1
                    created_findings.append({"title": finding["title"], "severity": finding["severity"]})
                    log(f"    ↳ 已登记发现（{severity}）：{title}")
        except Exception as exc:  # noqa: BLE001
            row["summary"] = f"失败：{type(exc).__name__}: {str(exc)[:80]}"
            log(f"    ↳ 跳过：{row['summary']}")
            rows.append(row)

    # 按阈值推送批量发现摘要（避免逐条轰炸）
    threshold = notify_min_severity()
    notable = [f for f in created_findings if severity_at_least(f["severity"], threshold)]
    if notable:
        lines = [f"{f['severity']} · {f['title']}" for f in notable[:5]]
        if len(notable) > 5:
            lines.append(f"…等共 {len(notable)} 条（阈值 {threshold}）")
        if notify_summary("[Sentinel] 批量研判：新发现", lines):
            log("已推送 webhook 通知（批量发现摘要）")

    # 聚合报告
    lines = [
        f"# 批量研判报告（{kind}）",
        "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 目标数：{len(targets)} · 有风险项：{risky} · 自动登记发现：{findings_created}",
        "",
        "| # | 目标 | 概要 | 风险 | 案件 |",
        "| --- | --- | --- | --- | --- |",
    ]
    for index, row in enumerate(rows, start=1):
        risk_text = "；".join(f"{r['severity']}:{r['reason']}" for r in row["risks"]) or "-"
        lines.append(f"| {index} | {row['target']} | {row['summary']} | {risk_text} | {row['case'] or '-'} |")
    lines += ["", "---", "", "本报告基于公开数据源与离线规则生成，仅用于防御与合法维权取证。"]
    (run_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
    (run_dir / "batch.json").write_text(
        json.dumps({"kind": kind, "when": datetime.now().isoformat(timespec="seconds"),
                    "rows": rows, "findings_created": findings_created}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    manifest = {
        "case": run_dir.name,
        "kind": f"batch-{kind}",
        "files": [
            {"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
            for p in sorted(run_dir.iterdir()) if p.is_file()
        ],
    }
    (run_dir / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    return {
        "dir": str(run_dir),
        "name": run_dir.name,
        "total": len(targets),
        "risky": risky,
        "findings_created": findings_created,
        "rows": rows,
    }
