$ErrorActionPreference = 'Stop'

# 任何安装错误都停留在窗口中，避免 PowerShell 一闪而过。
trap {
  $message = $_.Exception.Message
  Write-Host ''
  Write-Host '安装失败，详细信息如下：' -ForegroundColor Red
  Write-Host $message -ForegroundColor Red
  Write-Host ''
  try {
    $logPath = Join-Path $env:TEMP 'WpywMailInstaller-error.log'
    "时间：$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`r`n错误：$message`r`n位置：$($_.InvocationInfo.PositionMessage)" | Set-Content -LiteralPath $logPath -Encoding UTF8
    Write-Host "错误日志：$logPath" -ForegroundColor Yellow
  } catch { }
  Read-Host '请记录上面的错误信息，然后按回车键退出'
  exit 1
}

function Test-Administrator {
  $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = [Security.Principal.WindowsPrincipal]::new($identity)
  return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Administrator)) {
  $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
  Start-Process powershell.exe -Verb RunAs -ArgumentList $args -Wait
  exit $LASTEXITCODE
}

Write-Host ''
Write-Host 'wpyw.mail 邮箱服务安装程序' -ForegroundColor Cyan
Write-Host '本安装程序已经预填第一个邮箱：wpy@wpyw.site。' -ForegroundColor Yellow
Write-Host '安装过程中只需要输入密码；密码不会写入安装程序文件。' -ForegroundColor Yellow
Write-Host '提示：所有“直接回车”都表示使用方括号中的默认值或留空。' -ForegroundColor DarkGray
Write-Host ''

$defaultInstall = Join-Path ${env:ProgramFiles} 'WpywMail'
$defaultData = 'C:\WpywMailData'
$installDir = Read-Host "程序安装目录 [$defaultInstall]"
if ([string]::IsNullOrWhiteSpace($installDir)) { $installDir = $defaultInstall }
$dataDir = Read-Host "邮件数据目录（邮件会保存在这里） [$defaultData]"
if ([string]::IsNullOrWhiteSpace($dataDir)) { $dataDir = $defaultData }

do {
  $password = Read-Host '邮箱密码（至少 12 位，登录 wpy@wpyw.site 使用）' -AsSecureString
  $passwordPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
  try { $passwordText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($passwordPtr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($passwordPtr) }
  if ($passwordText.Length -lt 12) { Write-Host '密码太短，请重新输入至少 12 位密码。' -ForegroundColor Red }
} while ($passwordText.Length -lt 12)

$relayHost = Read-Host 'SMTP 外发中继服务器（可选；留空则按收件人 MX 直接投递）'
$relayPort = 587
$relayUser = ''
$relayPassword = ''
if (-not [string]::IsNullOrWhiteSpace($relayHost)) {
  $relayPortText = Read-Host 'SMTP 外发中继端口 [587]'
  if (-not [string]::IsNullOrWhiteSpace($relayPortText)) {
    if (-not [int]::TryParse($relayPortText, [ref]$relayPort) -or $relayPort -lt 1 -or $relayPort -gt 65535) { throw 'SMTP 中继端口必须是 1 到 65535 之间的数字。' }
  }
  $relayUser = Read-Host 'SMTP 中继账号（没有就直接回车）'
  if (-not [string]::IsNullOrWhiteSpace($relayUser)) {
    $relayPasswordSecure = Read-Host 'SMTP 中继密码' -AsSecureString
    $relayPasswordPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($relayPasswordSecure)
    try { $relayPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($relayPasswordPtr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($relayPasswordPtr) }
  }
}
$deliveryMode = if ([string]::IsNullOrWhiteSpace($relayHost)) { 'direct' } else { 'relay' }

$tlsPath = Read-Host 'mail.wpyw.site 的 PFX 证书路径（没有就直接回车，安装器会临时生成）'
$tlsPassword = ''
if (-not [string]::IsNullOrWhiteSpace($tlsPath)) {
  $tlsPasswordSecure = Read-Host 'PFX 证书密码（没有密码就直接回车）' -AsSecureString
  $tlsPasswordPtr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($tlsPasswordSecure)
  try { $tlsPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($tlsPasswordPtr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($tlsPasswordPtr) }
}

if ([string]::IsNullOrWhiteSpace($tlsPath)) {
  $certDir = Join-Path $dataDir 'certs'
  New-Item -ItemType Directory -Force -Path $certDir | Out-Null
  $tlsPath = Join-Path $certDir 'mail.wpyw.site.pfx'
  $tlsPassword = [guid]::NewGuid().ToString('N')
  $cert = New-SelfSignedCertificate -DnsName 'mail.wpyw.site' -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName 'wpyw.mail temporary TLS' -NotAfter (Get-Date).AddYears(2) -KeyExportPolicy Exportable
  $secureCertPassword = ConvertTo-SecureString -String $tlsPassword -AsPlainText -Force
  Export-PfxCertificate -Cert $cert -FilePath $tlsPath -Password $secureCertPassword | Out-Null
  Write-Host '未填写证书，已生成临时自签名 TLS 证书。正式使用前请替换为受信任证书。' -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $installDir, $dataDir | Out-Null
$payloadFiles = Get-ChildItem -LiteralPath $PSScriptRoot -File | Where-Object { $_.Name -notin @('install.ps1', 'install.cmd') }
foreach ($file in $payloadFiles) { Copy-Item -LiteralPath $file.FullName -Destination (Join-Path $installDir $file.Name) -Force }

$settings = [ordered]@{
  Domain = 'wpyw.site'
  Hostname = 'mail.wpyw.site'
  HttpPrefix = 'http://127.0.0.1:8787/'
  SmtpPort = 25
  SubmissionPort = 587
  DataDirectory = $dataDir
  AdminEmail = 'wpy@wpyw.site'
  AdminPassword = $passwordText
  TlsCertificatePath = $tlsPath
  TlsCertificatePassword = $tlsPassword
  DeliveryMode = $deliveryMode
  DirectDelivery = [ordered]@{
    ConnectionTimeoutSeconds = 30
    CommandTimeoutSeconds = 30
    DnsTimeoutSeconds = 5
    OpportunisticStartTls = $true
    RequireStartTls = $false
    DnsServer = ''
  }
  Relay = [ordered]@{ Host = $relayHost; Port = $relayPort; User = $relayUser; Password = $relayPassword; EnableSsl = $true }
}
$settings | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $installDir 'appsettings.json') -Encoding UTF8

New-NetFirewallRule -DisplayName 'wpyw.mail SMTP 邮件端口' -Direction Inbound -Protocol TCP -LocalPort 25,587 -Action Allow -ErrorAction SilentlyContinue | Out-Null
$exe = Join-Path $installDir 'WpywMail.Native.exe'
$action = New-ScheduledTaskAction -Execute $exe -WorkingDirectory $installDir
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'WpywMail' -Action $action -Trigger $trigger -Principal $principal -Settings $taskSettings -Force | Out-Null
Start-ScheduledTask -TaskName 'WpywMail'

Write-Host ''
Write-Host '安装完成。' -ForegroundColor Green
Write-Host '邮箱地址：wpy@wpyw.site'
Write-Host "程序目录：$installDir"
Write-Host "邮件数据目录：$dataDir"
Write-Host '收信 SMTP：25    客户端发信：587    本机 API：127.0.0.1:8787'
Write-Host 'Cloudflare Tunnel 的 Web/API 路由应指向：http://127.0.0.1:8787/'
if ($deliveryMode -eq 'direct') {
  Write-Host '当前使用 MX 直投模式：服务端会查询收件人域名的 MX，并连接对方 25 端口发送。' -ForegroundColor Yellow
} else {
  Write-Host '当前使用 SMTP 中继模式：邮件会交给你填写的中继服务器发送。' -ForegroundColor Yellow
}
Write-Host ''
Read-Host '按回车键退出'
