# Sentinel - Windows host check v2 (read-only audit; optional baseline/diff)
# Usage:
#   pwsh -File posture_windows.ps1              # full report
#   pwsh -File posture_windows.ps1 -Baseline    # full report + save snapshot JSON
#   pwsh -File posture_windows.ps1 -Diff        # compare with the latest snapshot
param(
    [switch]$Baseline,
    [switch]$Diff
)

$ErrorActionPreference = 'SilentlyContinue'
$OutDir = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Write-Section($t) {
    Write-Output ''
    Write-Output ('=' * 8 + ' ' + $t + ' ' + '=' * 8)
}

function Get-PortRuleMap {
    # port -> list of "RuleName[Profile]" for enabled inbound Allow rules
    $map = @{}
    $filters = @()
    for ($i = 0; $i -lt 3; $i++) {
        $filters = @(Get-NetFirewallPortFilter -ErrorAction SilentlyContinue)
        if ($filters.Count -gt 0) { break }
        Start-Sleep -Seconds 1
    }
    if ($filters.Count -eq 0) {
        Write-Output '  (warning: firewall port filter query failed - allow rules not shown)'
        return $map
    }
    foreach ($pf in $filters) {
        $ports = @($pf.LocalPort)
        foreach ($p in $ports) {
            if ($p -notmatch '^\d+$') { continue }
            foreach ($r in @($pf | Get-NetFirewallRule)) {
                if ("$($r.Enabled)" -eq 'True' -and "$($r.Direction)" -eq 'Inbound' -and "$($r.Action)" -eq 'Allow') {
                    $label = '{0}[{1}]' -f $r.DisplayName, $r.Profile
                    if (-not $map.ContainsKey($p)) { $map[$p] = New-Object System.Collections.Generic.List[string] }
                    if (-not $map[$p].Contains($label)) { $map[$p].Add($label) }
                }
            }
        }
    }
    return $map
}

function Get-Snapshot {
    $hosts = @(
        Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" |
            Where-Object { $_ -match '^\s*\d' -and $_ -notmatch '^\s*#' } |
            ForEach-Object { $_.Trim() }
    )

    $certs = @()
    foreach ($store in @('Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root')) {
        $certs += @(Get-ChildItem $store | ForEach-Object { '{0}|{1}' -f $_.Thumbprint, $_.Subject })
    }
    $certs = @($certs | Sort-Object -Unique)

    $ports = @()
    foreach ($c in @(Get-NetTCPConnection -State Listen)) {
        if ($c.LocalAddress -in @('0.0.0.0', '::')) {
            $pname = (Get-Process -Id $c.OwningProcess).ProcessName
            $ports += ('{0}|{1}' -f $c.LocalPort, $pname)
        }
    }
    $ports = @($ports | Sort-Object -Unique)

    $av = @()
    $av += @(Get-CimInstance -Namespace 'root/SecurityCenter2' -ClassName AntiVirusProduct |
        ForEach-Object { 'wsc:{0}:{1}' -f $_.displayName, $_.productState })
    $av += @(Get-Process | Where-Object {
            $_.ProcessName -match '^(HipsDaemon|HipsTray|wsctrlsvc|QQPCMgr|360Tray|360Safe|avp|ekrn|avastui)$'
        } | ForEach-Object { 'proc:' + $_.ProcessName })
    $av = @($av | Sort-Object -Unique)

    $tasks = @(
        Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } |
            ForEach-Object { $_.TaskPath + $_.TaskName + '|' + $_.State }
    )

    # 非回环 hosts 映射（加速器一般写 127.0.0.1；映射到其他 IP 的条目更值得核对）
    $hostsOther = @($hosts | Where-Object { $_ -notmatch '^\s*(127\.0\.0\.1|::1|0\.0\.0\.0)\s' })

    # 关键加固状态（写入基线参与 diff）
    $rdpVal = (Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -ErrorAction SilentlyContinue).fDenyTSConnections
    if ($null -eq $rdpVal) { $rdp = @('unknown') } elseif ($rdpVal -eq 0) { $rdp = @('enabled') } else { $rdp = @('disabled') }

    $smb1Val = $null
    try { $smb1Val = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol } catch { }
    if ($null -eq $smb1Val) { $smb1 = @('unknown(need-admin)') } elseif ($smb1Val) { $smb1 = @('enabled') } else { $smb1 = @('disabled') }

    $firewall = @(Get-NetFirewallProfile | ForEach-Object { '{0}|enabled={1}|inbound={2}' -f $_.Name, $_.Enabled, $_.DefaultInboundAction })

    $proxyItem = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    $proxy = @('enable={0}|server={1}' -f $proxyItem.ProxyEnable, $proxyItem.ProxyServer)

    $admins = @(Get-LocalGroupMember -Group Administrators -ErrorAction SilentlyContinue | ForEach-Object { $_.Name })
    if ($admins.Count -eq 0) { $admins = @('unavailable(need-admin)') }

    $llmnrPolicy = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction SilentlyContinue).EnableMulticast
    if ($null -eq $llmnrPolicy) { $llmnr = @('policy=unset(default-on)') } else { $llmnr = @('policyEnableMulticast=' + $llmnrPolicy) }

    $netbios = @(
        Get-CimInstance Win32_NetworkAdapterConfiguration -ErrorAction SilentlyContinue |
            Where-Object { $_.IPEnabled } |
            ForEach-Object { '{0}|TcpipNetbiosOptions={1}' -f $_.Description, $_.TcpipNetbiosOptions }
    )

    $autoruns = @()
    foreach ($runKey in @(
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
            'HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run'
        )) {
        $item = Get-ItemProperty $runKey -ErrorAction SilentlyContinue
        if (-not $item) { continue }
        $hive = if ($runKey.StartsWith('HKCU')) { 'HKCU' } else { 'HKLM' }
        foreach ($prop in @($item.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' })) {
            $autoruns += ('{0}|{1}={2}' -f $hive, $prop.Name, $prop.Value)
        }
    }
    foreach ($startup in @(
            (Join-Path $env:APPDATA 'Microsoft\Windows\Start Menu\Programs\Startup'),
            (Join-Path $env:ProgramData 'Microsoft\Windows\Start Menu\Programs\Startup')
        )) {
        if (Test-Path $startup) {
            $autoruns += @(Get-ChildItem $startup -ErrorAction SilentlyContinue | ForEach-Object { 'startup|' + $_.Name })
        }
    }
    $autoruns = @($autoruns | Sort-Object -Unique)

    return [ordered]@{
        capturedAt = (Get-Date).ToString('s')
        hosts      = $hosts
        hostsOther = $hostsOther
        certs      = $certs
        ports      = $ports
        av         = $av
        tasks      = $tasks
        rdp        = $rdp
        smb1       = $smb1
        firewall   = $firewall
        proxy      = $proxy
        admins     = $admins
        llmnr      = $llmnr
        netbios    = $netbios
        autoruns   = $autoruns
    }
}

function Compare-Section($name, $old, $new) {
    $old = @($old); $new = @($new)
    $added   = @($new | Where-Object { $_ -notin $old })
    $removed = @($old | Where-Object { $_ -notin $new })
    if ($added.Count -eq 0 -and $removed.Count -eq 0) {
        Write-Output ('[=] ' + $name + ': no change')
        return
    }
    Write-Output ('[!] ' + $name + (': +{0} -{1}' -f $added.Count, $removed.Count))
    foreach ($a in $added)   { Write-Output ('  + ' + $a) }
    foreach ($r in $removed) { Write-Output ('  - ' + $r) }
}

$snap = Get-Snapshot

if ($Diff) {
    $latest = Get-ChildItem $OutDir -Filter 'baseline-*.json' | Sort-Object Name | Select-Object -Last 1
    if (-not $latest) {
        Write-Output 'No baseline found. Run with -Baseline first.'
        exit 1
    }
    $old = Get-Content $latest.FullName -Raw | ConvertFrom-Json
    Write-Output ('Diff vs {0} (captured {1})' -f $latest.Name, $old.capturedAt)
    Compare-Section 'hosts' $old.hosts $snap.hosts
    Compare-Section 'certs' $old.certs $snap.certs
    Compare-Section 'ports' $old.ports $snap.ports
    Compare-Section 'av'    $old.av    $snap.av
    Compare-Section 'tasks' $old.tasks $snap.tasks
    Compare-Section 'hostsOther' $old.hostsOther $snap.hostsOther
    Compare-Section 'rdp'      $old.rdp      $snap.rdp
    Compare-Section 'smb1'     $old.smb1     $snap.smb1
    Compare-Section 'firewall' $old.firewall $snap.firewall
    Compare-Section 'proxy'    $old.proxy    $snap.proxy
    Compare-Section 'admins'   $old.admins   $snap.admins
    Compare-Section 'llmnr'    $old.llmnr    $snap.llmnr
    Compare-Section 'netbios'  $old.netbios  $snap.netbios
    Compare-Section 'autoruns' $old.autoruns $snap.autoruns
    exit 0
}

Write-Output ('Sentinel host check v2 @ ' + (Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))

Write-Section '1. Endpoint protection (AV)'
foreach ($a in $snap.av) { Write-Output ('  ' + $a) }
$third = @($snap.av | Where-Object { $_ -match '^proc:' })
$def = Get-MpComputerStatus
if ($third.Count -gt 0) {
    Write-Output ('  => Third-party AV active: ' + ($third -join ', '))
    Write-Output '  => Defender RealTimeProtection=False is EXPECTED while third-party AV runs.'
} elseif ($def -and -not $def.RealTimeProtectionEnabled) {
    Write-Output '  !! No active AV detected and Defender real-time protection is OFF. Fix required.'
} else {
    Write-Output '  => Defender real-time protection is ON.'
}

Write-Section '2. Firewall profiles'
Get-NetFirewallProfile | ForEach-Object {
    Write-Output ('  ' + $_.Name + ' enabled=' + $_.Enabled + ' defaultInbound=' + $_.DefaultInboundAction)
}

Write-Section '3. RDP / SMB1'
Write-Output ('  RDP: ' + $snap.rdp[0] + $(if ($snap.rdp[0] -eq 'enabled') { '  [review] 如不需要远程桌面，建议关闭' } else { '' }))
Write-Output ('  SMB1: ' + $snap.smb1[0] + $(if ($snap.smb1[0] -eq 'enabled') { '  [review] 老旧协议，建议关闭' } else { '' }))

Write-Section '4. All-interface listening ports + firewall inbound allow rules'
$ruleMap = Get-PortRuleMap
$knownServicePorts = @('3306', '33060', '445', '139', '135', '3389', '5900', '6379', '27017', '11211', '2375', '1433', '5432', '9200')
foreach ($entry in ($snap.ports | Sort-Object { [int]($_.Split('|')[0]) })) {
    $port, $proc = $entry.Split('|')
    $suffix = ''
    if ($ruleMap.ContainsKey($port)) { $suffix = ' <- ALLOW: ' + ($ruleMap[$port] -join '; ') }
    if ($knownServicePorts -contains $port) { $suffix += ' [review]' }
    Write-Output ('  {0,5} {1}{2}' -f $port, $proc, $suffix)
}

Write-Section '5. Custom hosts mappings'
Write-Output ('  count: ' + $snap.hosts.Count)
$snap.hosts | Select-Object -First 40 | ForEach-Object { Write-Output ('  ' + $_) }
Write-Output ('  non-loopback entries (核对项): ' + $snap.hostsOther.Count)
$snap.hostsOther | Select-Object -First 20 | ForEach-Object { Write-Output ('    ! ' + $_) }

Write-Section '6. System proxy'
$p = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
Write-Output ('  ProxyEnable=' + $p.ProxyEnable + ' ProxyServer=' + $p.ProxyServer)

Write-Section '7. Local administrators'
Get-LocalGroupMember -Group Administrators | ForEach-Object { Write-Output ('  ' + $_.Name) }

Write-Section '8. Root certificates'
Write-Output ('  count: ' + $snap.certs.Count + ' (full list goes into baseline snapshot)')
$snap.certs | Select-Object -First 10 | ForEach-Object { Write-Output ('  ' + $_) }

Write-Section '9. Scheduled tasks (non-Microsoft)'
$snap.tasks | Select-Object -First 30 | ForEach-Object { Write-Output ('  ' + $_) }

Write-Section '10. LLMNR / NetBIOS (name-resolution poisoning surface)'
$snap.llmnr | ForEach-Object { Write-Output ('  LLMNR ' + $_) }
$snap.netbios | ForEach-Object { Write-Output ('  NetBIOS ' + $_ + $(if ($_ -match 'TcpipNetbiosOptions=0$') { '  [review] 建议按接口关闭' } else { '' })) }

Write-Section '11. Autoruns (logon entries)'
Write-Output ('  count: ' + $snap.autoruns.Count)
$snap.autoruns | Select-Object -First 30 | ForEach-Object { Write-Output ('  ' + $_) }

if ($Baseline) {
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $path = Join-Path $OutDir ('baseline-' + $stamp + '.json')
    $snap | ConvertTo-Json -Depth 5 | Set-Content -Path $path -Encoding utf8
    Write-Output ''
    Write-Output ('Baseline saved: ' + $path)
} else {
    Write-Output ''
    Write-Output 'Tip: -Baseline to snapshot, -Diff to compare against the latest snapshot.'
}
