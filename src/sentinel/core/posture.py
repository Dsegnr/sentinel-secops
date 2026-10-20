"""主机体检基线的派生信息：待加固项清单 + 基线差异对比（供工作台 / 巡检复用）。"""

from __future__ import annotations

# 参与差异对比的基线字段（与 posture_windows.ps1 的 -Diff 保持一致）
DIFF_KEYS = (
    "hosts", "hostsOther", "ports", "certs", "tasks", "av",
    "autoruns", "rdp", "smb1", "firewall", "proxy", "admins", "llmnr", "netbios",
)


def diff_baselines(old: dict, new: dict, keys: tuple[str, ...] = DIFF_KEYS, limit: int = 30) -> dict:
    """比较两份基线，返回 {字段: {added: [...], removed: [...]}}（只含变化的字段）。"""
    result: dict = {}
    for key in keys:
        old_set = {str(x) for x in (old.get(key) or [])}
        new_set = {str(x) for x in (new.get(key) or [])}
        added = sorted(new_set - old_set)[:limit]
        removed = sorted(old_set - new_set)[:limit]
        if added or removed:
            result[key] = {"added": added, "removed": removed}
    return result


def baseline_issues(data: dict) -> list[str]:
    """从基线 JSON 推导"待加固项"（保守：只列明确的加固点）。"""
    issues: list[str] = []
    rdp = (data.get("rdp") or ["?"])[0]
    if rdp == "enabled":
        issues.append("RDP 远程桌面已开启（如不需要建议关闭）")
    smb1 = (data.get("smb1") or ["?"])[0]
    if smb1 == "enabled":
        issues.append("SMBv1 仍启用（老旧协议，建议关闭）")
    for row in data.get("firewall") or []:
        if "enabled=False" in str(row):
            issues.append(f"防火墙配置档未启用：{str(row).split('|')[0]}")
    llmnr = str((data.get("llmnr") or ["?"])[0])
    if llmnr.startswith("policy=unset"):
        issues.append("LLMNR 未禁用（局域网名称解析投毒面，可组策略关闭）")
    netbios_on = sum(1 for item in (data.get("netbios") or []) if str(item).endswith("=0"))
    if netbios_on:
        issues.append(f"NetBIOS over TCP/IP 在 {netbios_on} 个网卡上开启（建议按网卡禁用）")
    other = data.get("hostsOther") or []
    if other:
        issues.append(f"hosts 存在 {len(other)} 条非回环映射（需人工核对是否你添加的）")
    return issues
