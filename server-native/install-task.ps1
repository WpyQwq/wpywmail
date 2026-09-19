param(
  [string]$InstallDirectory = 'C:\WpywMail',
  [string]$TaskName = 'WpywMail'
)

$exe = Join-Path $InstallDirectory 'WpywMail.Native.exe'
if (-not (Test-Path -LiteralPath $exe)) {
  throw "找不到 $exe，请先把 self-contained publish 目录复制到服务器。"
}

$action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $InstallDirectory
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force
Start-ScheduledTask -TaskName $TaskName
Write-Host "已注册并启动任务：$TaskName"
