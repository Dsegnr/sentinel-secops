# Sentinel 工作台一键启动（默认 http://127.0.0.1:8787）
# 用法：右键"使用 PowerShell 运行"，或命令行执行： pwsh -File scripts\workbench.ps1
$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')
if (-not (Test-Path '.\.venv\Scripts\sentinel-web.exe')) {
    Write-Host '未找到 .venv，请先执行: python -m venv .venv; .\.venv\Scripts\python.exe -m pip install -e .[web]'
    exit 1
}
Write-Host 'Sentinel 工作台启动中... 浏览器访问 http://127.0.0.1:8787 （Ctrl+C 退出）'
& '.\.venv\Scripts\sentinel-web.exe' --host 127.0.0.1 --port 8787
