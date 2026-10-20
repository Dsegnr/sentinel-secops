"""统一数据模型：所有研判结果收敛到 Finding / SourceResult / TriageReport。"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _now() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Confidence(str, Enum):
    CONFIRMED = "confirmed"      # 权威源直接给出（如离线库解析）
    LIKELY = "likely"            # 多源一致或规则明确
    UNVERIFIED = "unverified"    # 单源 / 推测
    UNAVAILABLE = "unavailable"  # 源不可达或无法判定（不等于否定）


@dataclass
class SourceResult:
    source: str
    ok: bool
    detail: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    key: str
    value: str
    confidence: Confidence = Confidence.UNVERIFIED
    source: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["confidence"] = self.confidence.value
        return data


@dataclass
class TriageReport:
    kind: str
    target: str
    findings: list[Finding] = field(default_factory=list)
    sources: list[SourceResult] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    created_at: str = field(default_factory=_now)

    def add(self, key: str, value: Any, confidence: Confidence = Confidence.UNVERIFIED, source: str = "") -> None:
        self.findings.append(Finding(key=key, value=str(value), confidence=confidence, source=source))

    def note(self, text: str) -> None:
        self.notes.append(text)

    def has_key(self, key: str) -> bool:
        return any(f.key == key for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "target": self.target,
            "created_at": self.created_at,
            "findings": [f.to_dict() for f in self.findings],
            "sources": [s.to_dict() for s in self.sources],
            "notes": list(self.notes),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
