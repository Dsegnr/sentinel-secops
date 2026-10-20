"""共享配置：CLI 与工作台共用（config/config.yaml、项目根定位）。"""

from __future__ import annotations

import os
from pathlib import Path

import yaml


def load_config() -> dict:
    """依次尝试 ./config/config.yaml 与仓库根 config/config.yaml。"""
    candidates = [
        Path.cwd() / "config" / "config.yaml",
        Path(__file__).resolve().parents[3] / "config" / "config.yaml",
    ]
    for candidate in candidates:
        if candidate.is_file():
            return yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    return {}


def project_root() -> Path:
    """定位项目根：优先 SENTINEL_HOME，其次 cwd（当含 kb/cases/config），最后源码树根。"""
    env = os.environ.get("SENTINEL_HOME", "").strip()
    if env and Path(env).is_dir():
        return Path(env).resolve()
    cwd = Path.cwd()
    if any((cwd / name).exists() for name in ("kb", "cases", "config", "checks")):
        return cwd.resolve()
    return Path(__file__).resolve().parents[3]
