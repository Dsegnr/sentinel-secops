"""资产台账：域名 / IP / 号码 / 主机 / 账号的档案与关联。"""

from __future__ import annotations

import uuid
from datetime import datetime
from pathlib import Path

from .store import JsonStore

ASSET_TYPES = ("ip", "domain", "phone", "host", "account", "other")

_KIND_TO_TYPE = {"ip": "ip", "phone": "phone", "user": "account", "username": "account", "mailbox": "account"}


def kind_to_type(kind: str) -> str:
    return _KIND_TO_TYPE.get((kind or "").lower(), "other")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class AssetStore:
    def __init__(self, data_dir: Path):
        self.store = JsonStore(Path(data_dir) / "assets.json")

    def list(self, type_: str | None = None) -> list[dict]:
        items = self.store.load()
        if type_:
            items = [a for a in items if a.get("type") == type_]
        return sorted(items, key=lambda a: a.get("updated_at", ""), reverse=True)

    def get(self, asset_id: str) -> dict | None:
        return next((a for a in self.store.load() if a.get("id") == asset_id), None)

    def upsert(
        self,
        type_: str,
        value: str,
        label: str = "",
        tags: list[str] | None = None,
        note: str = "",
        case: str | None = None,
    ) -> dict:
        value = (value or "").strip()
        type_ = type_ if type_ in ASSET_TYPES else "other"
        items = self.store.load()
        for asset in items:
            if asset.get("type") == type_ and asset.get("value") == value:
                if case and case not in asset.setdefault("cases", []):
                    asset["cases"].append(case)
                if label and not asset.get("label"):
                    asset["label"] = label
                if note and not asset.get("note"):
                    asset["note"] = note
                if tags:
                    merged = list(dict.fromkeys((asset.get("tags") or []) + list(tags)))
                    asset["tags"] = merged
                asset["updated_at"] = _now()
                self.store.save(items)
                return asset
        asset = {
            "id": "a-" + uuid.uuid4().hex[:8],
            "type": type_,
            "value": value,
            "label": label,
            "tags": list(tags or []),
            "note": note,
            "cases": [case] if case else [],
            "created_at": _now(),
            "updated_at": _now(),
        }
        items.append(asset)
        self.store.save(items)
        return asset

    def add_note(self, asset_id: str, text: str) -> None:
        items = self.store.load()
        for asset in items:
            if asset.get("id") == asset_id:
                prefix = f"[{_now()}] {text}"
                asset["note"] = (asset.get("note") + "\n" if asset.get("note") else "") + prefix
                asset["updated_at"] = _now()
        self.store.save(items)

    def link_case(self, asset_id: str, case: str) -> None:
        items = self.store.load()
        for asset in items:
            if asset.get("id") == asset_id:
                if case not in asset.setdefault("cases", []):
                    asset["cases"].append(case)
                asset["updated_at"] = _now()
        self.store.save(items)
