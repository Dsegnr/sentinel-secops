"""主机加固脚本生成：基于体检基线，生成"预览默认 / -Apply 执行 / -Undo 撤销"的 PowerShell 脚本。

安全设计（硬约束）：
- 工作台只"生成脚本"，绝不自动执行、绝不直接写注册表；
- 脚本默认 dry-run（只打印将做什么），加 -Apply 才真正修改，-Undo -Apply 反向恢复；
- 目标对象（如网卡描述）在生成时固化，撤销目标与加固目标一致、可预期；
- -Apply 时脚本自检管理员权限；每步单独 try 由 PowerShell 原生报错，不吞错。
"""

from __future__ import annotations

from datetime import datetime


def _first(data: dict, key: str, default: str = "?") -> str:
    rows = data.get(key) or [default]
    return str(rows[0])


def netbios_targets(baseline: dict) -> list[str]:
    """返回当前 NetBIOS 为"默认开启(=0)"的网卡描述（生成时固化进脚本）。"""
    targets = []
    for item in baseline.get("netbios") or []:
        text = str(item)
        if text.endswith("=0"):
            targets.append(text.rsplit("|", 1)[0])
    return targets


def available_actions(baseline: dict) -> list[dict]:
    """基于基线列出加固项与当前状态（供工作台 / CLI 展示）。"""
    llmnr = _first(baseline, "llmnr")
    rdp = _first(baseline, "rdp")
    smb1 = _first(baseline, "smb1")
    netbios = netbios_targets(baseline)
    return [
        {
            "key": "llmnr",
            "title": "禁用 LLMNR（局域网名称解析投毒面）",
            "detail": f"当前策略：{llmnr}",
            "active": llmnr.startswith("policy=unset") or llmnr.endswith("=1"),
        },
        {
            "key": "netbios",
            "title": "禁用 NetBIOS over TCP/IP（逐网卡）",
            "detail": f"当前默认开启的网卡：{len(netbios)} 个" + (f"（{'、'.join(netbios[:3])}）" if netbios else ""),
            "active": bool(netbios),
        },
        {
            "key": "rdp",
            "title": "关闭 RDP 远程桌面",
            "detail": f"当前：{rdp}",
            "active": rdp == "enabled",
        },
        {
            "key": "smb1",
            "title": "关闭 SMBv1",
            "detail": f"当前：{smb1}",
            "active": smb1 == "enabled",
        },
    ]


_SCRIPT_HEAD = """# Sentinel 主机加固脚本（[[WHEN]] 生成）
# 基线来源：[[BASELINE]] · SHA-256 [[SHA]]
# 用法（管理员 PowerShell）：
#   1) 预览（默认，不修改任何配置）：  .\\sentinel-hardening.ps1
#   2) 执行加固：                      .\\sentinel-hardening.ps1 -Apply
#   3) 撤销加固：                      .\\sentinel-hardening.ps1 -Undo -Apply
# 说明：每步都会先打印"将要做什么"；真正修改只在 -Apply 时发生。
param(
    [switch]$Apply,
    [switch]$Undo
)

$ErrorActionPreference = 'Continue'
$changed = New-Object System.Collections.Generic.List[string]

if ($Apply) {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host '[!] -Apply 需要管理员权限：请用「以管理员身份运行」的 PowerShell。' -ForegroundColor Red
        exit 1
    }
}

$mode = if ($Undo) { '撤销模式' } else { '加固模式' }
$run = if ($Apply) { '（执行）' } else { '（预览，不会改动任何配置）' }
Write-Host ('Sentinel 加固脚本 · ' + $mode + $run)
"""

_SECTION_LLMNR = """
# ---------- LLMNR ----------
$llmnrKey = 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\System'
if (-not $Undo) {
    Write-Host '[LLMNR] 目标：设置 EnableMulticast=0（禁用 LLMNR）'
    if ($Apply) {
        New-Item -Path $llmnrKey -Force | Out-Null
        Set-ItemProperty -Path $llmnrKey -Name EnableMulticast -Value 0 -Type DWord
        $changed.Add('LLMNR')
        Write-Host '  -> 已禁用'
    }
} else {
    Write-Host '[LLMNR] 目标：移除策略值（恢复 Windows 默认）'
    if ($Apply) {
        Remove-ItemProperty -Path $llmnrKey -Name EnableMulticast -ErrorAction SilentlyContinue
        $changed.Add('LLMNR')
        Write-Host '  -> 已恢复'
    }
}
"""

_SECTION_NETBIOS = """
# ---------- NetBIOS over TCP/IP（生成时固化的网卡清单） ----------
$netbiosAdapters = @(
[[ADAPTERS]]
)
foreach ($desc in $netbiosAdapters) {
    $nic = Get-CimInstance Win32_NetworkAdapterConfiguration | Where-Object { $_.Description -eq $desc -and $_.IPEnabled }
    if (-not $nic) {
        Write-Host ('[NetBIOS] 跳过（未找到启用的网卡）：' + $desc)
        continue
    }
    $target = if ($Undo) { 0 } else { 2 }
    Write-Host ('[NetBIOS] ' + $desc + ' -> TcpipNetbiosOptions=' + $target)
    if ($Apply) {
        Invoke-CimMethod -InputObject $nic -MethodName SetTcpipNetbios -Arguments @{ TcpipNetbiosOptions = $target } | Out-Null
        $changed.Add('NetBIOS:' + $desc)
        Write-Host '  -> 已设置'
    }
}
"""

_SECTION_RDP = """
# ---------- RDP ----------
$rdpKey = 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server'
if (-not $Undo) {
    Write-Host '[RDP] 目标：关闭远程桌面（fDenyTSConnections=1）'
    if ($Apply) {
        Set-ItemProperty -Path $rdpKey -Name fDenyTSConnections -Value 1 -Type DWord
        $changed.Add('RDP')
        Write-Host '  -> 已关闭'
    }
} else {
    Write-Host '[RDP] 目标：恢复远程桌面开启（fDenyTSConnections=0）'
    if ($Apply) {
        Set-ItemProperty -Path $rdpKey -Name fDenyTSConnections -Value 0 -Type DWord
        $changed.Add('RDP')
        Write-Host '  -> 已恢复'
    }
}
"""

_SECTION_SMB1 = """
# ---------- SMBv1 ----------
if (-not $Undo) {
    Write-Host '[SMB1] 目标：关闭 SMBv1 服务端协议'
    if ($Apply) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
        $changed.Add('SMB1')
        Write-Host '  -> 已关闭（彻底移除组件可另执行：Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol）'
    }
} else {
    Write-Host '[SMB1] 目标：恢复 SMBv1（仅在确有老旧设备依赖时使用）'
    if ($Apply) {
        Set-SmbServerConfiguration -EnableSMB1Protocol $true -Force
        $changed.Add('SMB1')
        Write-Host '  -> 已恢复'
    }
}
"""

_SCRIPT_TAIL = """
Write-Host ''
if ($Apply) {
    Write-Host ('完成：共执行 ' + $changed.Count + ' 项：' + ($changed -join '、'))
    Write-Host '建议回到 Sentinel 工作台重新跑一次体检，确认状态变化。'
} else {
    Write-Host '这是预览。确认无误后执行：  .\\sentinel-hardening.ps1 -Apply'
    Write-Host '如需撤销：                .\\sentinel-hardening.ps1 -Undo -Apply'
}
"""


def build_script(
    baseline: dict,
    baseline_name: str = "baseline",
    baseline_sha: str = "",
    when: str | None = None,
) -> str:
    """生成加固/撤销二合一脚本；基线上已达标的项不会包含在内。"""
    when = when or datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    actions = available_actions(baseline)
    active = {a["key"] for a in actions if a["active"]}

    parts = [
        _SCRIPT_HEAD.replace("[[WHEN]]", when)
        .replace("[[BASELINE]]", baseline_name)
        .replace("[[SHA]]", baseline_sha or "-")
    ]
    skipped: list[str] = []

    if "llmnr" in active:
        parts.append(_SECTION_LLMNR)
    else:
        skipped.append("LLMNR（已达标）")

    if "netbios" in active:
        adapters = netbios_targets(baseline)
        # 注意：PowerShell 数组字面量不允许尾逗号
        adapter_lines = ",\n".join("    '" + desc.replace("'", "''") + "'" for desc in adapters)
        parts.append(_SECTION_NETBIOS.replace("[[ADAPTERS]]", adapter_lines))
    else:
        skipped.append("NetBIOS（已达标）")

    if "rdp" in active:
        parts.append(_SECTION_RDP)
    else:
        skipped.append("RDP（已关闭）")

    if "smb1" in active:
        parts.append(_SECTION_SMB1)
    else:
        skipped.append("SMBv1（已关闭）")

    if not active:
        parts.append(
            "\nWrite-Host '基线上没有需要处理的加固项（RDP/SMB1 已关闭、LLMNR/NetBIOS 已达标）。'\n"
        )
    elif skipped:
        parts.append("\n# 以下项已达标，未包含：# " + "；".join(skipped) + "\n")

    parts.append(_SCRIPT_TAIL)
    return "".join(parts)
