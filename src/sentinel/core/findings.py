"""发现管理：severity / status 生命周期 + 关联案件与资产。"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from .store import JsonStore

SEVERITIES = ("info", "low", "medium", "high", "critical")
STATUSES = ("open", "triaged", "mitigated", "accepted", "closed")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class FindingStore:
    def __init__(self, data_dir: Path):
        self.store = JsonStore(Path(data_dir) / "findings.json")

    def list(self, status: str | None = None, severity: str | None = None) -> list[dict]:
        items = self.store.load()
        if status:
            items = [f for f in items if f.get("status") == status]
        if severity:
            items = [f for f in items if f.get("severity") == severity]
        return sorted(items, key=lambda f: f.get("updated_at", ""), reverse=True)

    def stats(self) -> dict:
        items = self.store.load()
        open_items = [f for f in items if f.get("status") != "closed"]
        by_severity: dict[str, int] = {}
        for item in open_items:
            key = item.get("severity", "info")
            by_severity[key] = by_severity.get(key, 0) + 1
        return {"total": len(items), "open": len(open_items), "by_severity": by_severity}

    def get(self, fid: str) -> dict | None:
        return next((f for f in self.store.load() if f.get("id") == fid), None)

    def create(
        self,
        title: str,
        severity: str = "info",
        detail: str = "",
        source: str = "manual",
        case: str | None = None,
        asset: str | None = None,
    ) -> dict:
        item = {
            "id": "f-" + uuid.uuid4().hex[:8],
            "title": (title or "").strip() or "(未命名发现)",
            "severity": severity if severity in SEVERITIES else "info",
            "status": "open",
            "source": source,
            "case": case,
            "asset": asset,
            "detail": detail or "",
            "notes": [],
            "created_at": _now(),
            "updated_at": _now(),
        }
        items = self.store.load()
        items.append(item)
        self.store.save(items)
        return item

    def set_status(self, fid: str, status: str, note: str | None = None) -> dict | None:
        if status not in STATUSES:
            return None
        items = self.store.load()
        updated = None
        for item in items:
            if item.get("id") == fid:
                item["status"] = status
                item["updated_at"] = _now()
                if note:
                    item.setdefault("notes", []).append({"ts": _now(), "text": note})
                updated = item
        self.store.save(items)
        return updated

    def add_note(self, fid: str, text: str) -> None:
        items = self.store.load()
        for item in items:
            if item.get("id") == fid:
                item.setdefault("notes", []).append({"ts": _now(), "text": text})
                item["updated_at"] = _now()
        self.store.save(items)

    def list_by_asset(self, asset_id: str) -> list[dict]:
        return [f for f in self.list() if f.get("asset") == asset_id]

    def list_by_case(self, case: str) -> list[dict]:
        return [f for f in self.list() if f.get("case") == case]
