"""JSON 轻量存储：线程锁 + 原子写入（本地单机使用）。"""

from __future__ import annotations

import json
import threading
from pathlib import Path


class JsonStore:
    _locks: dict[str, threading.Lock] = {}
    _locks_guard = threading.Lock()

    def __init__(self, path: Path):
        self.path = Path(path).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with JsonStore._locks_guard:
            lock = JsonStore._locks.get(str(self.path))
            if lock is None:
                lock = threading.Lock()
                JsonStore._locks[str(self.path)] = lock
        self._lock = lock
        if not self.path.is_file():
            self.path.write_text("[]", encoding="utf-8")

    def load(self) -> list[dict]:
        with self._lock:
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                return data if isinstance(data, list) else []
            except Exception:  # noqa: BLE001
                return []

    def save(self, items: list[dict]) -> None:
        with self._lock:
            tmp = self.path.with_suffix(self.path.suffix + ".tmp")
            tmp.write_text(json.dumps(items, ensure_ascii=False, indent=2), encoding="utf-8")
            tmp.replace(self.path)
