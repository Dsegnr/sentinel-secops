"""Sentinel CLI 入口：sentinel phone|ip|user|case。"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from pathlib import Path

from . import __version__
from .core.blocklist import BlocklistStore
from .core.case import save_case
from .core.config import load_config
from .core.export import export_case
from .core.http import HttpClient, inject_os_truststore
from .core.report import render
from .modules import ip as ip_mod
from .modules import phone as phone_mod
from .modules import username as user_mod


def _platforms_path() -> Path:
    return Path(__file__).resolve().parent / "data" / "platforms.yaml"


def _case_kind_target(case_dir: Path) -> tuple[str, str]:
    """案件类型/目标：report.json 优先，批量案件回退 batch.json。"""
    report_json = case_dir / "report.json"
    if report_json.is_file():
        try:
            data = json.loads(report_json.read_text(encoding="utf-8"))
            return str(data.get("kind", "-")), str(data.get("target", "-"))
        except Exception:  # noqa: BLE001
            pass
    batch_json = case_dir / "batch.json"
    if batch_json.is_file():
        try:
            data = json.loads(batch_json.read_text(encoding="utf-8"))
            return f"batch-{data.get('kind', '?')}", f"{len(data.get('rows') or [])} 个目标"
        except Exception:  # noqa: BLE001
            pass
    return "-", "-"


def _run_case(args, cfg: dict) -> int:
    cases_dir = Path(args.cases_dir or cfg.get("cases_dir") or "cases")

    if args.action == "grep":
        from .core.case import grep_cases

        keyword = " ".join(args.name or []).strip()
        if not keyword:
            print("用法: sentinel case grep <关键字> [--kind ip] [--limit N]")
            return 2
        items = []
        for case in sorted((p for p in cases_dir.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True):
            kind, target = _case_kind_target(case)
            items.append({"name": case.name, "kind": kind, "target": target})
        if args.kind:
            items = [item for item in items if item["kind"] == args.kind]
        hits = grep_cases(cases_dir, items, keyword, limit=args.limit)
        if not hits:
            print("没有命中。")
            return 0
        for hit in hits:
            print(f"[{hit['kind']}] {hit['name']} · {hit['target']}")
            print(f"    …{hit['snippet']}…")
        print(f"\n共 {len(hits)} 条命中（在 report.md / report.json 正文中检索）。")
        return 0

    if args.action in ("archive", "restore", "archived", "delete"):
        from .core.case import ARCHIVE_DIRNAME, archive_cases, delete_archived, restore_cases

        if args.action == "archived":
            archive = cases_dir / ARCHIVE_DIRNAME
            dirs = (
                sorted((p for p in archive.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True)
                if archive.is_dir()
                else []
            )
            if not dirs:
                print("归档库为空。")
                return 0
            for case in dirs:
                kind, target = _case_kind_target(case)
                print(f"{case.name}  [{kind}] {target}")
            print(f"\n共 {len(dirs)} 个归档案件。")
            return 0

        names = [str(n) for n in (args.name or [])]
        if not names:
            print(f"用法: sentinel case {args.action} <案件名...>")
            return 2
        if args.action == "archive":
            result = archive_cases(cases_dir, names)
            print(f"已归档 {len(result['archived'])} 个" + (f"，跳过：{'、'.join(result['skipped'][:5])}" if result["skipped"] else ""))
            return 0
        if args.action == "restore":
            result = restore_cases(cases_dir, names)
            print(f"已恢复 {len(result['restored'])} 个" + (f"，跳过：{'、'.join(result['skipped'][:5])}" if result["skipped"] else ""))
            return 0
        if not args.yes:
            print("永久删除需要显式确认：sentinel case delete <案件名...> --yes")
            return 2
        result = delete_archived(cases_dir, names, confirm="DELETE")
        print(f"已永久删除 {len(result['deleted'])} 个" + (f"，跳过：{'、'.join(result['skipped'][:5])}" if result["skipped"] else ""))
        return 0

    if args.action == "list":
        if not cases_dir.is_dir():
            print("没有案件目录。")
            return 0
        from rich.console import Console
        from rich.table import Table

        table = Table(title="案件列表")
        table.add_column("案件")
        table.add_column("类型")
        table.add_column("目标")
        for case in sorted((p for p in cases_dir.iterdir() if p.is_dir()), key=lambda p: p.name, reverse=True):
            kind, target = _case_kind_target(case)
            table.add_row(case.name, kind, target)
        Console().print(table)
        return 0

    if args.action == "pack":
        from .core.pack import build_package

        names = [str(n) for n in (args.name or [])]
        try:
            filename, content = build_package(cases_dir, names, template=args.template)
        except ValueError as exc:
            print(f"打包失败：{exc}")
            return 2
        out = Path(args.out) if args.out else Path(filename)
        out.write_bytes(content)
        scope = f"{len(names)} 个指定案件" if names else "全部案件"
        print(f"已打包（{scope}）→ {out.resolve()}（{len(content) / 1024:.0f} KB）")
        return 0

    if not args.name:
        print("用法: sentinel case export <案件目录名> [--format html|md] [--out PATH]")
        return 2
    case_dir = cases_dir / args.name[0]
    if not case_dir.is_dir():
        print(f"案件不存在: {case_dir}")
        return 2
    filename, content = export_case(case_dir, args.format, template=args.template)
    out = Path(args.out) if args.out else Path(filename)
    out.write_text(content, encoding="utf-8")
    print(f"已导出: {out.resolve()}")
    return 0


def _run_patrol(args) -> int:
    from .core.tasks import TaskManager

    manager = TaskManager(Path.cwd())
    task = manager.submit(
        "patrol",
        "命令行巡检",
        {"posture": True, "kind": "", "target": "", "ai": bool(args.ai)},
    )
    deadline = time.time() + 600
    state = None
    while time.time() < deadline:
        state = next((t for t in manager.list() if t["id"] == task.id), None)
        if state and state["status"] in ("done", "failed"):
            break
        time.sleep(1)
    if not state or state["status"] not in ("done", "failed"):
        print("巡检超时")
        return 1
    print("\n".join(state["log"]))
    print("结果：", state["result"] or state["status"])
    return 0 if state["status"] == "done" else 1


def _run_blocklist(args) -> int:
    store = BlocklistStore(Path.cwd() / "data")
    if args.action == "check":
        if not args.value:
            print("用法: sentinel blocklist check <IP>")
            return 2
        hits = store.check_ip(args.value)
        if hits:
            for hit in hits:
                print(f"命中: {hit['source']} · {hit['cidr']}")
        else:
            print("未命中本地封堵清单（FireHOL level1 / Spamhaus DROP）。")
        return 0
    if args.action == "export":
        fmt = (args.value or "ps1").lower()
        if fmt == "csv":
            content = store.export_csv()
            default_name = "sentinel-blocklist.csv"
        else:
            content = store.export_firewall_script()
            default_name = "sentinel-firewall-block.ps1"
        if args.out:
            out = Path(args.out)
            out.write_text(content, encoding="utf-8")
            print(f"已导出: {out.resolve()}")
        else:
            print(f"# （未指定 --out，直接打印；建议重定向到 {default_name}）")
            print(content)
        return 0
    # update
    cfg = load_config()
    client = HttpClient(
        timeout=float(cfg.get("timeout", 8) or 8),
        proxy=(cfg.get("proxy") or "").strip() or None,
    )
    results = store.update(client)
    for key, value in results.items():
        if value.get("ok"):
            print(f"{key}: OK（{value.get('count')} 条）")
        else:
            print(f"{key}: FAIL（{value.get('error', '')[:120]}）")
    return 0


def _run_batch(args) -> int:
    from .core.assets import AssetStore
    from .core.batch import parse_targets, run_batch
    from .core.findings import FindingStore

    path = Path(args.path)
    if not path.is_absolute():
        path = Path.cwd() / path
    if not path.is_file():
        print(f"文件不存在：{path}")
        return 2
    targets = parse_targets(path.read_text(encoding="utf-8", errors="ignore"))
    if not targets:
        print("目标列表为空。")
        return 2
    cfg = load_config()
    client = HttpClient(
        timeout=float(cfg.get("timeout", 8) or 8),
        proxy=(cfg.get("proxy") or "").strip() or None,
    )
    cases_dir = Path(args.cases_dir or cfg.get("cases_dir") or "cases")
    summary = run_batch(
        args.kind,
        targets,
        client,
        cases_dir,
        findings_store=FindingStore(Path.cwd() / "data"),
        assets_store=AssetStore(Path.cwd() / "data"),
        blocklist=BlocklistStore(Path.cwd() / "data"),
        log=print,
        save=not args.no_save,
    )
    print(f"批量完成：{summary['total']} 项 · 风险 {summary['risky']} · 自动发现 {summary['findings_created']}")
    print(f"报告：{summary['dir']}")
    return 0


def _run_sources(args) -> int:
    from .core.sources_health import run_checks

    data = run_checks()
    for row in data["results"]:
        flag = "OK  " if row.get("ok") else "FAIL"
        detail = row.get("error") or row.get("sample", "")
        print(f"{flag} {row['name']:<24} {row['ms']:>6}ms  {str(detail)[:90]}")
    print(f"\n可用 {data['ok']}/{data['total']}")
    out = Path(args.out) if args.out else Path.cwd() / "checks" / "out" / "sources-health.json"
    try:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"结果已写入：{out}")
    except Exception as exc:  # noqa: BLE001
        print(f"（结果写入失败，不影响检测：{exc}）")
    return 0


def _run_harden(args) -> int:
    from .core.hardening import available_actions, build_script

    out_dir = Path.cwd() / "checks" / "out"
    files = sorted(out_dir.glob("baseline-*.json")) if out_dir.is_dir() else []
    if not files:
        print("还没有体检基线：先运行 `sentinel patrol` 或在工作台总览点一次体检。")
        return 2
    path = files[-1]
    data = json.loads(path.read_text(encoding="utf-8"))
    sha = hashlib.sha256(path.read_bytes()).hexdigest()
    for action in available_actions(data):
        flag = "待加固" if action["active"] else "已达标"
        print(f"[{flag}] {action['title']} | {action['detail']}")
    content = build_script(data, baseline_name=path.name, baseline_sha=sha)
    if args.out == "-":
        print(content)
        return 0
    out = Path(args.out)
    out.write_text(content, encoding="utf-8")
    print(f"\n已生成：{out.resolve()}")
    print("用法：预览直接运行；执行加 -Apply；撤销加 -Undo -Apply（需管理员）。")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="安全研判工具链（仅公开数据源；用于防御与合法维权取证）",
    )
    parser.add_argument("--version", action="version", version=f"sentinel {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_phone = sub.add_parser("phone", help="电话号码研判（离线号段元数据）")
    p_phone.add_argument("target")
    p_phone.add_argument("--region", default=None, help="无国家码时按此地区解析，如 CN")

    p_ip = sub.add_parser("ip", help="IP 研判（地理 / ASN / 网络性质 / 反查 / RDAP）")
    p_ip.add_argument("target")

    p_user = sub.add_parser("user", help="用户名跨平台探活（存在 / 未发现 / 无法判定）")
    p_user.add_argument("target")
    p_user.add_argument("--only", default=None, help="逗号分隔的平台名，如 github,gitee,pypi")

    p_domain = sub.add_parser("domain", help="域名体检（WHOIS/DNS/邮件安全/子域/TLS/安全头）")
    p_domain.add_argument("target")

    p_url = sub.add_parser("url", help="URL 安全检查（结构特征 / 重定向链 / 域名属性）")
    p_url.add_argument("target")

    p_breach = sub.add_parser("breach", help="密码泄露自查（HIBP k-匿名；仅限自查自己的凭据）")
    p_breach.add_argument("password", nargs="?", help="密码（建议改用 --stdin，避免进入命令历史）")
    p_breach.add_argument("--stdin", action="store_true", help="从标准输入读取密码")

    p_email = sub.add_parser("email", help="邮件头分析（钓鱼研判，输入原始邮件文件）")
    p_email.add_argument("path", help="原始邮件（.eml / 文本）路径")

    p_mailbox = sub.add_parser("mailbox", help="邮箱研判（服务商 / 一次性邮箱 / 邮件认证 / 公开头像 / 前缀跨平台）")
    p_mailbox.add_argument("target", help="邮箱地址，如 name@example.com")
    p_mailbox.add_argument("--platforms", action="store_true", help="对邮箱前缀做跨平台探活（较慢，31 平台）")

    p_block = sub.add_parser("blocklist", help="封堵清单：update / check / export（FireHOL / Spamhaus）")
    p_block.add_argument("action", choices=["update", "check", "export"])
    p_block.add_argument("value", nargs="?", help="check 时的 IP；export 时的格式（ps1|csv，默认 ps1）")
    p_block.add_argument("--out", default=None, help="export 的输出文件路径（默认打印到屏幕）")

    p_batch = sub.add_parser("batch", help="批量研判（每行一个目标；风险自动登记发现）")
    p_batch.add_argument("kind", choices=["ip", "phone", "user", "domain", "url", "mailbox"])
    p_batch.add_argument("path", help="目标列表文件（每行一个，支持 # 注释）")
    p_batch.add_argument("--cases-dir", default=None, help="案件目录（默认 ./cases）")
    p_batch.add_argument("--no-save", action="store_true", help="不落案件档")

    p_sources = sub.add_parser("sources", help="数据源健康检测（运行时依赖的公开源）")
    p_sources.add_argument("--out", default=None, help="结果 JSON 路径（默认 ./checks/out/sources-health.json）")

    p_harden = sub.add_parser("harden", help="生成主机加固脚本（基于最近体检基线；预览默认/-Apply/-Undo）")
    p_harden.add_argument("--out", default="sentinel-hardening.ps1", help="输出文件（默认 ./sentinel-hardening.ps1；- 表示打印到屏幕）")

    p_case = sub.add_parser("case", help="案件管理：list / export")
    p_case.add_argument(
        "action",
        choices=["list", "export", "pack", "grep", "archive", "restore", "archived", "delete"],
        help="list/export/pack/grep/archive/restore/archived/delete",
    )
    p_case.add_argument("name", nargs="*", help="export: 案件目录名；pack/archive/restore/delete: 案件名列表；grep: 关键字")
    p_case.add_argument("--format", choices=["html", "md"], default="html", help="导出格式（默认 html）")
    p_case.add_argument("--template", choices=["standard", "brief", "evidence"], default="standard", help="报告模板（默认 standard）")
    p_case.add_argument("--out", default=None, help="输出文件路径（默认写到当前目录）")
    p_case.add_argument("--cases-dir", default=None, help="案件目录（默认 ./cases）")
    p_case.add_argument("--kind", default=None, help="grep 时按案件类型过滤（如 ip / phone / domain）")
    p_case.add_argument("--limit", type=int, default=50, help="grep 命中上限（默认 50）")
    p_case.add_argument("--yes", action="store_true", help="delete 的显式确认（不可恢复）")

    p_patrol = sub.add_parser("patrol", help="运行一次巡检（体检 → 打包报告；供计划任务/脚本调用）")
    p_patrol.add_argument("--ai", action="store_true", help="附带 AI 解读")

    p_import = sub.add_parser("import", help="导入扫描结果（nuclei JSONL / CSV）为发现")
    p_import.add_argument("path", help="本地结果文件")
    p_import.add_argument("--format", choices=["auto", "nuclei", "csv"], default="auto")

    for p in (p_phone, p_ip, p_user, p_domain, p_url, p_breach, p_email, p_mailbox):
        p.add_argument("--no-save", action="store_true", help="不落案件档")
        p.add_argument("--cases-dir", default=None, help="案件目录（默认 ./cases）")
    return parser


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:  # noqa: BLE001
        pass
    args = _build_parser().parse_args(argv)

    inject_os_truststore()
    cfg = load_config()

    if args.cmd == "case":
        return _run_case(args, cfg)

    if args.cmd == "patrol":
        return _run_patrol(args)

    if args.cmd == "blocklist":
        return _run_blocklist(args)

    if args.cmd == "batch":
        return _run_batch(args)

    if args.cmd == "sources":
        return _run_sources(args)

    if args.cmd == "harden":
        return _run_harden(args)

    if args.cmd == "import":
        from .core.assets import AssetStore
        from .core.findings import FindingStore
        from .core.importers import import_file

        path = Path(args.path)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.is_file():
            print(f"文件不存在：{path}")
            return 2
        stats = import_file(
            path,
            args.format,
            FindingStore(Path.cwd() / "data"),
            AssetStore(Path.cwd() / "data"),
        )
        print(f"导入完成：新增 {stats['imported']} 条，跳过重复 {stats['skipped']} 条（共 {stats['total']}）。")
        return 0

    client = HttpClient(
        timeout=float(cfg.get("timeout", 8) or 8),
        proxy=(cfg.get("proxy") or "").strip() or None,
    )
    cases_dir = Path(args.cases_dir or cfg.get("cases_dir") or "cases")

    if args.cmd == "phone":
        report = phone_mod.triage(args.target, region=args.region, client=client)
    elif args.cmd == "ip":
        report = ip_mod.triage(args.target, client, blocklist=BlocklistStore(Path.cwd() / "data"))
    elif args.cmd == "user":
        only = [s.strip() for s in args.only.split(",")] if args.only else None
        report = user_mod.triage(args.target, client, _platforms_path(), only=only)
    elif args.cmd == "domain":
        from .modules import domain as domain_mod

        report = domain_mod.triage(args.target, client)
    elif args.cmd == "url":
        from .modules import url as url_mod

        report = url_mod.triage(args.target, client)
    elif args.cmd == "email":
        from .modules import emailhdr as email_mod

        path = Path(args.path)
        if not path.is_absolute():
            path = Path.cwd() / path
        if not path.is_file():
            print(f"文件不存在：{path}")
            return 2
        report = email_mod.triage(path.read_text(encoding="utf-8", errors="ignore"), client)
    elif args.cmd == "mailbox":
        from .modules import mailbox as mailbox_mod

        report = mailbox_mod.triage(
            args.target,
            client,
            platforms_path=_platforms_path() if args.platforms else None,
        )
    else:
        from .modules import breach as breach_mod

        password = sys.stdin.read().strip() if args.stdin else (args.password or "")
        if not password:
            print("用法: sentinel breach --stdin（推荐）或 sentinel breach <password>")
            return 2
        report = breach_mod.triage(password, client)

    render(report)
    if not args.no_save:
        case_dir = save_case(report, cases_dir)
        print(f"案件落档: {case_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
