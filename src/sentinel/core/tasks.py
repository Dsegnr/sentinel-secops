"""动作队列：串行执行巡检任务（主机体检 → 威胁研判 → 打包综合报告）。

轻量实现：单 worker 线程 + 内存队列 + checks/out/tasks.json 持久化。
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from .. import __version__
from ..modules import ip as ip_mod
from ..modules import phone as phone_mod
from ..modules import username as user_mod
from .ai import AIError, ai_available, summarize_report
from .assets import AssetStore
from .batch import run_batch
from .blocklist import BlocklistStore
from .case import save_case
from .config import load_config
from .findings import FindingStore
from .http import HttpClient, inject_os_truststore
from .notify import notify_finding, notify_summary
from .posture import DIFF_KEYS, baseline_issues, diff_baselines
from .sources_health import run_checks

_PLATFORMS = Path(__file__).resolve().parents[1] / "data" / "platforms.yaml"
_MAX_TASKS = 100


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


@dataclass
class Task:
    id: str
    kind: str
    title: str
    status: str = "queued"  # queued | running | done | failed
    log: list = field(default_factory=list)
    result: str = ""
    created: str = field(default_factory=_now)
    started: str = ""
    finished: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "status": self.status,
            "log": list(self.log),
            "result": self.result,
            "created": self.created,
            "started": self.started,
            "finished": self.finished,
        }


class TaskManager:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.cases_dir = self.root / "cases"
        self.out_dir = self.root / "checks" / "out"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.posture_script = self.root / "checks" / "posture_windows.ps1"
        self._state_file = self.out_dir / "tasks.json"
        self._lock = threading.Lock()
        self._tasks: list[Task] = []
        self._payloads: dict[str, dict] = {}
        self._worker: threading.Thread | None = None
        self._scheduler: threading.Thread | None = None
        self._schedule_interval_h: float = 0.0
        self._started_at: float = time.time()
        self._load()

    # ---- 公共接口 ----

    def submit(self, kind: str, title: str, payload: dict | None = None) -> Task:
        task = Task(id=uuid.uuid4().hex[:8], kind=kind, title=title)
        with self._lock:
            self._tasks.append(task)
            if payload:
                self._payloads[task.id] = payload
            if len(self._tasks) > _MAX_TASKS:
                self._tasks = self._tasks[-_MAX_TASKS:]
            self._save_locked()
        self._ensure_worker()
        return task

    def list(self) -> list[dict]:
        with self._lock:
            return [t.to_dict() for t in reversed(self._tasks)]

    # ---- 持久化 ----

    def _save_locked(self) -> None:
        try:
            data = [t.to_dict() for t in self._tasks]
            tmp = self._state_file.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self._state_file)
        except Exception:  # noqa: BLE001
            pass

    def _load(self) -> None:
        if not self._state_file.is_file():
            return
        try:
            items = json.loads(self._state_file.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return
        for item in items:
            task = Task(id=item.get("id", uuid.uuid4().hex[:8]), kind=item.get("kind", "?"), title=item.get("title", "?"))
            task.status = item.get("status", "done")
            task.log = list(item.get("log", []))
            if task.status in ("queued", "running"):
                task.status = "failed"
                task.log.append("进程重启，任务被中断")
            task.result = item.get("result", "")
            task.created = item.get("created", task.created)
            task.started = item.get("started", "")
            task.finished = item.get("finished", "")
            self._tasks.append(task)

    # ---- 队列循环 ----

    def _ensure_worker(self) -> None:
        with self._lock:
            if self._worker and self._worker.is_alive():
                return
            self._worker = threading.Thread(target=self._loop, daemon=True)
            self._worker.start()

    def enable_schedule(self, interval_hours: float) -> None:
        """启动周期巡检 + 每日摘要（工作台运行期间生效；到期判断基于持久化任务时间）。"""
        if self._scheduler and self._scheduler.is_alive():
            return
        self._schedule_interval_h = max(0.05, float(interval_hours))
        self._scheduler = threading.Thread(target=self._schedule_loop, daemon=True)
        self._scheduler.start()

    def _schedule_loop(self) -> None:
        while True:
            time.sleep(300)
            try:
                self._schedule_tick()
            except Exception:  # noqa: BLE001
                pass

    def _schedule_tick(self) -> None:
        cfg = load_config().get("monitor") or {}
        # 每日摘要：digest_hour（默认 9 点；-1 表示关闭）
        try:
            digest_hour = int(cfg.get("digest_hour", 9))
        except Exception:  # noqa: BLE001
            digest_hour = 9
        now = datetime.now()
        today = now.strftime("%Y-%m-%d")
        if digest_hour >= 0 and now.hour >= digest_hour and self._last_digest_date() != today and not self._busy("digest"):
            self._set_last_digest_date(today)
            self.submit("digest", "每日摘要（自动）", {})
        # 周期巡检：按"上一次完成时间"判断（跨重启有效）；从未跑过则最多 1 小时后补一次
        interval_s = self._schedule_interval_h * 3600
        last = self._last_patrol_epoch()
        grace = min(interval_s, 3600)
        due = (last is None and time.time() - self._started_at >= grace) or (
            last is not None and time.time() - last >= interval_s
        )
        if due and not self._busy():
            self.submit("patrol", "定时巡检（自动）", {"posture": True, "kind": "", "target": "", "ai": False})

    def _busy(self, kind: str | None = None) -> bool:
        with self._lock:
            return any(
                t.status in ("queued", "running") and (kind is None or t.kind == kind)
                for t in self._tasks
            )

    def _last_patrol_epoch(self) -> float | None:
        with self._lock:
            for task in reversed(self._tasks):
                if task.kind == "patrol" and task.status in ("done", "failed") and task.finished:
                    try:
                        return datetime.strptime(task.finished, "%Y-%m-%d %H:%M:%S").timestamp()
                    except ValueError:
                        continue
        return None

    def _digest_state_path(self) -> Path:
        return self.out_dir / "digest-state.json"

    def _last_digest_date(self) -> str:
        try:
            data = json.loads(self._digest_state_path().read_text(encoding="utf-8"))
            return str(data.get("last_date") or "")
        except Exception:  # noqa: BLE001
            return ""

    def _set_last_digest_date(self, value: str) -> None:
        try:
            self._digest_state_path().write_text(json.dumps({"last_date": value}), encoding="utf-8")
        except Exception:  # noqa: BLE001
            pass

    def _loop(self) -> None:
        while True:
            task: Task | None = None
            with self._lock:
                for candidate in self._tasks:
                    if candidate.status == "queued":
                        task = candidate
                        task.status = "running"
                        task.started = _now()
                        break
                self._save_locked()
            if task is None:
                return
            payload = self._payloads.get(task.id) or {}
            try:
                self._execute(task, payload)
                if task.status != "failed":
                    task.status = "done"
            except Exception as exc:  # noqa: BLE001
                task.status = "failed"
                task.log.append(f"失败：{type(exc).__name__}: {exc}")
            task.finished = _now()
            with self._lock:
                self._save_locked()

    # ---- 任务实现 ----

    def _execute(self, task: Task, payload: dict) -> None:
        if task.kind == "patrol":
            self._exec_patrol(task, payload)
        elif task.kind == "batch":
            self._exec_batch(task, payload)
        elif task.kind == "sources":
            self._exec_sources(task)
        elif task.kind == "digest":
            self._exec_digest(task)
        else:
            raise ValueError(f"未知任务类型: {task.kind}")

    def _exec_digest(self, task: Task) -> None:
        from .digest import build_digest, render_text

        digest = build_digest(self.root)
        text = render_text(digest)
        for line in text.splitlines()[1:]:
            task.log.append(line)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        (self.out_dir / f"digest-{stamp}.json").write_text(
            json.dumps(digest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        latest = self.out_dir / "digest-latest.json"
        latest.write_text(json.dumps(digest, ensure_ascii=False, indent=2), encoding="utf-8")
        sent = notify_summary("[Sentinel] 每日摘要", text.splitlines()[1:])
        task.log.append("摘要已推送 webhook" if sent else "未配置 webhook：摘要仅保存在本地（digest-latest.json）")
        task.result = str(latest)

    def _exec_batch(self, task: Task, payload: dict) -> None:
        kind = str(payload.get("kind") or "")
        targets = [str(t) for t in (payload.get("targets") or [])]
        if not kind or not targets:
            raise ValueError("批量任务缺少 kind / targets")
        cfg = load_config()
        inject_os_truststore()
        client = HttpClient(
            timeout=float(cfg.get("timeout", 8) or 8),
            proxy=(cfg.get("proxy") or "").strip() or None,
        )
        summary = run_batch(
            kind,
            targets,
            client,
            cases_dir=self.cases_dir,
            findings_store=FindingStore(self.root / "data"),
            assets_store=AssetStore(self.root / "data"),
            blocklist=BlocklistStore(self.root / "data"),
            log=lambda message: task.log.append(message),
        )
        task.result = summary["dir"]
        task.log.append(
            f"完成：{summary['total']} 项 · 风险 {summary['risky']} · 自动登记发现 {summary['findings_created']}"
        )

    def _exec_sources(self, task: Task) -> None:
        inject_os_truststore()
        data = run_checks()
        self.out_dir.mkdir(parents=True, exist_ok=True)
        path = self.out_dir / "sources-health.json"
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        for row in data["results"]:
            flag = "OK" if row.get("ok") else "FAIL"
            detail = row.get("error") or row.get("sample", "")
            task.log.append(f"{flag} {row['name']}（{row['ms']}ms）{str(detail)[:80]}")
        task.result = f"{path} · OK {data['ok']}/{data['total']}"

    def _exec_patrol(self, task: Task, payload: dict) -> None:
        self._maybe_refresh_blocklist(task)

        posture_info = None
        if payload.get("posture"):
            task.log.append("步骤 1/4：主机体检（Baseline）…")
            posture_info = self._run_posture(task)
            if posture_info and posture_info.get("latest"):
                try:
                    latest_data = json.loads(Path(posture_info["latest"]).read_text(encoding="utf-8"))
                    issues = baseline_issues(latest_data)
                    if issues:
                        task.log.append(f"加固建议（{len(issues)} 项）：" + "；".join(issues[:6]))
                except Exception:  # noqa: BLE001
                    pass

        triage_case = None
        triage_data = None
        kind = str(payload.get("kind") or "").strip()
        target = str(payload.get("target") or "").strip()
        if kind and target:
            task.log.append(f"步骤 2/4：威胁研判 {kind} {target} …")
            report = self._run_triage(kind, target)
            triage_case = save_case(report, self.cases_dir)
            triage_data = report.to_dict()
            task.log.append(f"研判完成，案件：{triage_case.name}")

        ai_text = None
        ai_error = None
        if payload.get("ai"):
            task.log.append("步骤 3/4：AI 解读（DeepSeek）…")
            try:
                ai_text = self._run_ai(posture_info, triage_data, target)
                task.log.append("AI 解读完成")
            except Exception as exc:  # noqa: BLE001
                ai_error = f"{type(exc).__name__}: {exc}"
                task.log.append(f"AI 解读失败（不阻塞任务）：{ai_error}")
        else:
            task.log.append("步骤 3/4：未启用 AI 解读，跳过")

        task.log.append("步骤 4/4：打包综合报告…")
        patrol_dir = self._pack_patrol(
            posture_info, triage_case, target or "host", ai_text=ai_text, ai_error=ai_error
        )
        task.result = str(patrol_dir)
        task.log.append(f"报告已生成：{patrol_dir}")

        diff = (posture_info or {}).get("diff") or {}
        changed = any(key in diff for key in DIFF_KEYS)
        if changed:
            finding = FindingStore(self.root / "data").create(
                "主机基线发生变化（巡检发现）",
                severity="low",
                detail=json.dumps(diff, ensure_ascii=False, indent=2),
                source="patrol",
                case=patrol_dir.name,
            )
            task.log.append(f"已登记发现 {finding['id']}（基线变化，待处理）")
            if notify_finding(finding):
                task.log.append("已推送 webhook 通知")

        # 巡检完成摘要（webhook 已配置时；monitor.notify_on_patrol: false 可关闭）
        monitor_cfg = load_config().get("monitor") or {}
        if monitor_cfg.get("notify_on_patrol", True):
            notify_lines: list[str] = []
            if posture_info:
                change_count = sum(
                    len(v.get("added") or []) + len(v.get("removed") or [])
                    for v in diff.values()
                    if isinstance(v, dict)
                )
                notify_lines.append(f"体检：{Path(str(posture_info.get('latest', ''))).name} · 变化 {change_count} 处")
            if triage_case:
                notify_lines.append(f"研判：{triage_case.name}")
            notify_lines.append(f"报告：{patrol_dir.name}")
            if notify_summary("[Sentinel] 巡检完成", notify_lines):
                task.log.append("巡检摘要已推送 webhook")

    def _maybe_refresh_blocklist(self, task: Task) -> None:
        """封堵清单过期自动更新（并入巡检链；失败不阻塞巡检）。"""
        from .blocklist import should_refresh

        cfg = load_config()
        threshold = float((cfg.get("monitor") or {}).get("blocklist_refresh_hours", 24) or 24)
        store = BlocklistStore(self.root / "data")
        age = store.age_hours()
        if not should_refresh(age, threshold):
            task.log.append(f"封堵清单：{age:.0f}h 前更新，跳过（阈值 {threshold:.0f}h）")
            return
        why = "尚未下载" if age is None else f"已 {age:.0f}h 未更新"
        task.log.append(f"封堵清单：{why}，自动更新…")
        try:
            inject_os_truststore()
            client = HttpClient(timeout=60, proxy=(cfg.get("proxy") or "").strip() or None)
            results = store.update(client)
            summary = "；".join(
                f"{key} " + (f"OK（{value.get('count')} 条）" if value.get("ok") else f"FAIL（{str(value.get('error'))[:50]}）")
                for key, value in results.items()
            )
            task.log.append(f"封堵清单更新：{summary}")
        except Exception as exc:  # noqa: BLE001
            task.log.append(f"封堵清单更新失败（不阻塞巡检）：{type(exc).__name__}: {exc}")

    def _run_ai(self, posture_info: dict | None, triage_data: dict | None, target: str) -> str:
        if not ai_available():
            raise AIError("未配置 AI（config/config.yaml 的 ai.api_key）")
        ai_input: dict = {"kind": "patrol", "target": target or "host", "posture": None, "triage": None}
        if posture_info:
            ai_input["posture"] = {
                "baseline": Path(str(posture_info.get("latest", ""))).name,
                "diff": posture_info.get("diff") or {},
            }
        if triage_data:
            ai_input["triage"] = {
                "kind": triage_data.get("kind"),
                "target": triage_data.get("target"),
                "findings": triage_data.get("findings"),
                "notes": triage_data.get("notes"),
            }
        return summarize_report(ai_input)

    def _run_posture(self, task: Task) -> dict | None:
        if not self.posture_script.is_file():
            task.log.append("找不到体检脚本，跳过")
            return None
        before = sorted(self.out_dir.glob("baseline-*.json"))
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(self.posture_script), "-Baseline"],
            cwd=str(self.root),
            capture_output=True,
            timeout=600,
        )
        if proc.returncode != 0:
            task.log.append(f"体检脚本返回码 {proc.returncode}")
        after = sorted(self.out_dir.glob("baseline-*.json"))
        if not after:
            task.log.append("体检未产出基线文件")
            return None
        latest = after[-1]
        prev = before[-1] if before else None
        task.log.append(f"体检完成：{latest.name}")
        return {"latest": str(latest), "diff": self._baseline_diff(prev, latest)}

    def _baseline_diff(self, prev: Path | None, latest: Path) -> dict:
        try:
            new_data = json.loads(latest.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {}
        if prev is None:
            return {"note": "首次基线（无对比）"}
        try:
            old_data = json.loads(prev.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {"note": f"上一基线解析失败：{prev.name}"}
        return {"prev": prev.name, "latest": latest.name, **diff_baselines(old_data, new_data)}

    def _run_triage(self, kind: str, target: str):
        cfg = load_config()
        inject_os_truststore()
        client = HttpClient(
            timeout=float(cfg.get("timeout", 8) or 8),
            proxy=(cfg.get("proxy") or "").strip() or None,
        )
        if kind == "phone":
            return phone_mod.triage(target, client=client)
        if kind == "ip":
            return ip_mod.triage(target, client, blocklist=BlocklistStore(self.root / "data"))
        if kind == "user":
            if not user_mod.handle_ok(target):
                raise ValueError("用户名格式不合法（不支持空格/斜杠等特殊字符，支持中文，≤64 位）")
            return user_mod.triage(target, client, _PLATFORMS)
        if kind == "domain":
            from ..modules import domain as domain_mod

            return domain_mod.triage(target, client)
        if kind == "url":
            from ..modules import url as url_mod

            return url_mod.triage(target, client)
        raise ValueError(f"未知研判类型: {kind}")

    def _pack_patrol(
        self,
        posture_info: dict | None,
        triage_case: Path | None,
        slug: str,
        ai_text: str | None = None,
        ai_error: str | None = None,
    ) -> Path:
        stamp = datetime.now().strftime("%Y%m%dT%H%M%S")
        safe_slug = "".join(ch if ch.isalnum() or ch in "-._+" else "_" for ch in slug)[:40] or "host"
        patrol_dir = self.cases_dir / f"{stamp}-patrol-{safe_slug}"
        patrol_dir.mkdir(parents=True, exist_ok=True)

        lines = [
            "# 综合巡检报告（Patrol）",
            "",
            f"- 生成时间：{_now()}",
            f"- 工具：Sentinel v{__version__}",
            "",
            "## 一、主机体检",
        ]
        references: list[Path] = []
        if posture_info:
            lines.append(f"- 基线文件：{posture_info['latest']}")
            diff = posture_info.get("diff") or {}
            lines.append(f"- 基线对比：{diff.get('note') or json.dumps(diff, ensure_ascii=False)}")
            latest_path = Path(posture_info["latest"])
            if latest_path.is_file():
                references.append(latest_path)
        else:
            lines.append("- （本次未执行体检）")

        lines += ["", "## 二、威胁研判"]
        if triage_case:
            report_md = triage_case / "report.md"
            if report_md.is_file():
                lines.append(report_md.read_text(encoding="utf-8"))
                references.append(report_md)
            lines.append(f"- 案件目录：{triage_case}")
        else:
            lines.append("- （本次未执行研判）")

        lines += ["", "## 三、AI 解读（自动）"]
        if ai_text:
            lines.append(ai_text)
        elif ai_error:
            lines.append(f"（AI 解读失败：{ai_error}）")
        else:
            lines.append("（本次未启用 AI 解读）")

        lines += ["", "## 四、关联证据（SHA-256）"]
        for ref in references:
            digest = hashlib.sha256(ref.read_bytes()).hexdigest()
            lines.append(f"- `{ref}` — sha256:{digest}")

        (patrol_dir / "report.md").write_text("\n".join(lines), encoding="utf-8")
        (patrol_dir / "report.json").write_text(
            json.dumps(
                {
                    "kind": "patrol",
                    "target": slug,
                    "created_at": _now(),
                    "posture": posture_info,
                    "triage_case": triage_case.name if triage_case else None,
                    "ai": ai_text,
                    "ai_error": ai_error,
                },
                ensure_ascii=False,
                indent=2,
            ),
            encoding="utf-8",
        )
        manifest = {
            "case": patrol_dir.name,
            "created_at": _now(),
            "kind": "patrol",
            "files": [
                {"path": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
                for p in sorted(patrol_dir.iterdir())
                if p.is_file()
            ],
            "external_evidence": [
                {"path": str(ref), "sha256": hashlib.sha256(ref.read_bytes()).hexdigest()} for ref in references
            ],
        }
        (patrol_dir / "manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return patrol_dir
