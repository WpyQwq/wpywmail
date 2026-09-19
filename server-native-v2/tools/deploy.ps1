<#
.SYNOPSIS
  构建 → 自检 → 发布 → 部署到服务器 → 验证，一条命令完成 WpywMail 更新。

.EXAMPLE
  .\deploy.ps1 -Server <SERVER_IP> -RemotePassword '***'
  .\deploy.ps1 -Server <SERVER_IP> -RemotePassword '***' -FullCopy   # 首次部署或运行时变更时用
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [string]$RemoteUser = 'Administrator',
    [string]$RemotePassword,
    [string]$RemotePath = 'C:\Program Files\WpywMail',
    [string]$TaskName = 'WpywMail',
    [switch]$FullCopy,
    [switch]$SkipTests
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$publish = Join-Path (Split-Path -Parent $root) 'work\publish-v2'

function Step($text) { Write-Host "`n=== $text ===" -ForegroundColor Cyan }

Step '1) 构建'
Push-Location $root
try {
    & dotnet build -c Release -v q --nologo
    if ($LASTEXITCODE -ne 0) { throw '构建失败' }

    $exe = Join-Path $root 'bin\Release\net8.0\win-x64\WpywMail.Native.exe'

    if (-not $SkipTests) {
        Step '2) 自检'
        & $exe --selftest
        if ($LASTEXITCODE -ne 0) { throw '自检未通过，已中止部署' }
    }

    Step '3) 发布（自包含 win-x64）'
    & dotnet publish -c Release -r win-x64 --self-contained true -v q --nologo -o $publish
    if ($LASTEXITCODE -ne 0) { throw '发布失败' }
} finally { Pop-Location }

if ($RemotePassword) {
    $sec = ConvertTo-SecureString $RemotePassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("$Server\$RemoteUser", $sec)
} else {
    $cred = Get-Credential -UserName "$Server\$RemoteUser" -Message "连接 $Server 的凭据"
}

Step '4) 停服务'
$session = New-PSSession -ComputerName $Server -Credential $cred
try {
    Invoke-Command -Session $session -ArgumentList $TaskName -ScriptBlock {
        param($task)
        Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Get-CimInstance Win32_Process -Filter "Name='WpywMail.Native.exe'" |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    }

    Step '5) 传输文件'
    if ($FullCopy) {
        Write-Host '  全量复制（首次部署或运行时版本变更时使用）'
        Copy-Item -Path "$publish\*" -Destination $RemotePath -ToSession $session -Recurse -Force
    } else {
        Write-Host '  增量复制（仅程序集，约 400 KB）'
        foreach ($f in 'WpywMail.Native.dll', 'WpywMail.Native.exe', 'WpywMail.Native.pdb', 'WpywMail.Native.deps.json') {
            Copy-Item -Path (Join-Path $publish $f) -Destination "$RemotePath\" -ToSession $session -Force
        }
    }

    Step '6) 启动并验证'
    Invoke-Command -Session $session -ArgumentList $TaskName, $RemotePath -ScriptBlock {
        param($task, $path)
        # 启动前在服务器上再跑一次自检，确保部署的就是通过测试的二进制
        & (Join-Path $path 'WpywMail.Native.exe') --selftest | Select-String -Pattern '失败|=== 结果'
        Start-ScheduledTask -TaskName $task
        Start-Sleep -Seconds 7
        $p = Get-CimInstance Win32_Process -Filter "Name='WpywMail.Native.exe'"
        if (-not $p) { throw '服务未能启动' }
        "  运行中 PID: $($p.ProcessId)"
        Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue |
            Where-Object { $_.LocalPort -in 25, 587, 8787 } |
            ForEach-Object { "  监听 {0}:{1}" -f $_.LocalAddress, $_.LocalPort }
        Get-Content 'C:\WpywMailData\service.log' -Tail 4 -Encoding UTF8
    }
} finally {
    Remove-PSSession $session
}

Write-Host "`n部署完成。回滚：把 $RemotePath 换回 $RemotePath.v1-backup 并重启计划任务 $TaskName。" -ForegroundColor Green
