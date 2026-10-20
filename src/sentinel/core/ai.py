"""AI 辅助研判：让 LLM 对已采集的公开数据做综述与防守建议。

原则（与 Argus 的设计一致）：工具管事实、模型管推理——
只把研判报告里的结构化字段交给模型；不虚构、不执行任何针对目标的操作。
"""

from __future__ import annotations

import json
from typing import Any

from .config import load_config
from .http import HttpClient

_SYSTEM_PROMPT = (
    "你是网络安全研判助手。你会收到一份结构化研判报告（数据来自公开数据源与本地离线解析）。"
    "请只基于报告中的字段进行推理，不要虚构任何信息；无法判断时明确写'数据不足以判断'。"
    "输出要求：中文；先给一句话结论；再给风险级别（低/中/高/无法判断）；"
    "然后给 2-4 条行动建议（只允许防守方向：核实、阻断、举报、留证；严禁任何攻击性建议）。"
    "总长度 150-300 字。"
)


class AIError(RuntimeError):
    pass


def ai_config() -> dict:
    return load_config().get("ai") or {}


def ai_available() -> bool:
    return bool((ai_config().get("api_key") or "").strip())


def summarize_report(report: dict[str, Any]) -> str:
    cfg = ai_config()
    api_key = (cfg.get("api_key") or "").strip()
    if not api_key:
        raise AIError("未配置 AI：请在 config/config.yaml 的 ai.api_key 填入密钥。")
    base_url = (cfg.get("base_url") or "https://api.deepseek.com").rstrip("/")
    model = cfg.get("model") or "deepseek-chat"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(report, ensure_ascii=False)},
        ],
        "temperature": 0.2,
        "max_tokens": 800,
        "stream": False,
    }
    client = HttpClient(timeout=90, retries=0)
    resp = client.post(
        f"{base_url}/chat/completions",
        json_data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
    )
    if resp.status_code != 200:
        raise AIError(f"AI 接口返回 {resp.status_code}: {resp.text[:200]}")
    try:
        data = resp.json()
        return str(data["choices"][0]["message"]["content"]).strip()
    except Exception as exc:  # noqa: BLE001
        raise AIError(f"AI 响应解析失败：{exc}") from exc
