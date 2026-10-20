"""告警通知：可选的 webhook 推送（generic / feishu / slack 风格）+ 发现严重度阈值策略。"""

from __future__ import annotations

from .config import load_config
from .http import HttpClient

SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def notify(text: str, payload: dict | None = None) -> bool:
    """按 config.monitor.webhook_url 推送一条通知；未配置则静默返回 False。"""
    cfg = load_config().get("monitor") or {}
    url = (cfg.get("webhook_url") or "").strip()
    if not url:
        return False
    style = (cfg.get("webhook_style") or "generic").lower()
    if style == "feishu":
        body = {"msg_type": "text", "content": {"text": text}}
    elif style == "slack":
        body = {"text": text}
    else:
        body = {"text": text, "detail": payload or {}}
    try:
        client = HttpClient(timeout=10, retries=1)
        resp = client.post(url, json_data=body)
        return resp.status_code == 200
    except Exception:  # noqa: BLE001
        return False


def notify_min_severity() -> str:
    """推送阈值：monitor.notify_min_severity（默认 high）。"""
    cfg = load_config().get("monitor") or {}
    value = str(cfg.get("notify_min_severity") or "high").lower()
    return value if value in SEVERITY_ORDER else "high"


def severity_at_least(severity: str, threshold: str) -> bool:
    severity = str(severity or "info").lower()
    if severity not in SEVERITY_ORDER:
        severity = "info"
    if threshold not in SEVERITY_ORDER:
        threshold = "high"
    return SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)


def notify_finding(finding: dict) -> bool:
    """按阈值决定是否推送单个发现。"""
    severity = str(finding.get("severity") or "info")
    if not severity_at_least(severity, notify_min_severity()):
        return False
    return notify(f"[Sentinel] 新发现（{severity}）：{finding.get('title')}", payload=finding)


def notify_summary(title: str, lines: list[str]) -> bool:
    """推送多行摘要（巡检完成 / 批量研判 / 每日摘要等）。"""
    text = title + "\n" + "\n".join(f"· {line}" for line in lines if str(line).strip())
    return notify(text)
