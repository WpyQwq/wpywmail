<#
  账号体系真实验收（在邮件服务器本机执行）

  为什么必须跑真机：这套东西的价值全在「真的能注册、真的能登录、验证码邮件真的进得了信箱」，
  单元自检（--selftest）只能证明存储层与业务层的逻辑，证明不了 HTTP 链路、IMAP 链路、
  以及「验证码邮件是否真的投递到了客户端读得到的地方」。

  覆盖：
    A 策略接口、B 邀请码、C 本机托管地址注册即开通（含死循环回归）、D 会话/资料/审计、
    E 真实 IMAP 993 登录 + 收件箱非空、F 忘记密码→读信取码→重置、G 改密踢其他会话、
    H 登录失败锁定（423 + retryAfterSeconds）、I 管理员视角、J 停用后不能登录（并清理测试账号）

  用法：
    powershell -NoProfile -ExecutionPolicy Bypass -File account-acceptance.ps1
  退出码 = 失败项数（0 = 全通过）。
#>
param(
  [string]$Base = 'http://127.0.0.1:8787',
  [string]$ImapHost = '127.0.0.1',
  [int]$ImapPort = 993,
  [string]$ImapName = 'mail.example.com',
  [string]$Report = 'C:\Windows\Temp\wpyw-acct-verify.txt',
  [string]$AppSettings = 'C:\Program Files\WpywMail\appsettings.json'
)

$ErrorActionPreference = 'Stop'
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }

$script:pass = 0
$script:fail = 0
$script:skip = 0
# 注意：PowerShell 变量名大小写不敏感，这里不能叫 $script:report —— 会和参数 $Report 撞车
$script:logLines = New-Object System.Collections.Generic.List[string]

function Say([string]$line) {
  Write-Host $line
  $script:logLines.Add($line)
}
function Ok([string]$name, [bool]$cond, [string]$detail = '') {
  if ($cond) { $script:pass++; Say ("[PASS] {0}{1}" -f $name, $(if ($detail) { " —— $detail" } else { '' })) }
  else { $script:fail++; Say ("[FAIL] {0}{1}" -f $name, $(if ($detail) { " —— $detail" } else { '' })) }
}
function Skip([string]$name, [string]$why = '') {
  $script:skip++
  Say ("[SKIP] {0}{1}" -f $name, $(if ($why) { " —— $why" } else { '' }))
}

function Invoke-Api {
  param([string]$Method, [string]$Path, $Body = $null, [string]$Token = '')
  $headers = @{}
  if ($Token) { $headers['Authorization'] = "Bearer $Token" }
  $params = @{
    Uri = ($Base + $Path); Method = $Method; Headers = $headers
    UseBasicParsing = $true; TimeoutSec = 30
  }
  if ($null -ne $Body) {
    # 必须按 UTF-8 字节发，不能直接传字符串：控制台是 GBK，中文会变问号
    $params['Body'] = [Text.Encoding]::UTF8.GetBytes(($Body | ConvertTo-Json -Compress -Depth 8))
    $params['ContentType'] = 'application/json; charset=utf-8'
  }
  try {
    $r = Invoke-WebRequest @params
    $json = $null
    try { $json = $r.Content | ConvertFrom-Json } catch { }
    return @{ Code = [int]$r.StatusCode; Json = $json; Raw = $r.Content }
  } catch {
    $resp = $_.Exception.Response
    $code = 0
    $raw = ''
    if ($null -ne $resp) {
      try { $code = [int]$resp.StatusCode } catch { }
      try {
        $reader = New-Object IO.StreamReader($resp.GetResponseStream(), [Text.Encoding]::UTF8)
        $raw = $reader.ReadToEnd()
        $reader.Close()
      } catch { }
    }
    # ⚠ PowerShell 5.1 的坑：非 2xx 响应体常常已经被它的错误格式化逻辑读掉了，
    #   这时 GetResponseStream() 读出来是空的 —— 必须回退到 ErrorDetails.Message。
    if (-not $raw) {
      try { if ($_.ErrorDetails -and $_.ErrorDetails.Message) { $raw = $_.ErrorDetails.Message } } catch { }
    }
    $json = $null
    if ($raw) { try { $json = $raw | ConvertFrom-Json } catch { } }
    return @{ Code = $code; Json = $json; Raw = $raw }
  }
}

function Field($obj, [string]$name, $fallback = $null) {
  if ($null -eq $obj) { return $fallback }
  $p = $obj.PSObject.Properties[$name]
  if ($null -ne $p -and $null -ne $p.Value) { return $p.Value }
  return $fallback
}

# /api/login 直接把会话对象摊在顶层（{token,expiresAt,user}），/api/register 则包在 session 里。
# 两种形状都得认，否则会静默取到空 token，后面全用着已失效的 token 连锁失败（踩过）。
function Get-Token($json) {
  $t = [string](Field (Field $json 'session') 'token' '')
  if (-not $t) { $t = [string](Field $json 'token' '') }
  return $t
}

function Wait-InboxMessage {
  param([string]$Token, [string]$SubjectLike, [int]$Seconds = 40)
  for ($i = 0; $i -lt $Seconds; $i++) {
    $r = Invoke-Api 'GET' '/api/messages?folder=inbox&limit=20' $null $Token
    $list = Field $r.Json 'messages'
    if ($r.Code -eq 200 -and $null -ne $list) {
      foreach ($m in $list) {
        $s = [string](Field $m 'subject' '')
        if ($s -like $SubjectLike) { return $m }
      }
    }
    Start-Sleep -Seconds 1
  }
  return $null
}

function Read-ImapUntil {
  param($Reader, [string]$Tag, [int]$MaxLines = 500)
  $out = New-Object System.Collections.Generic.List[string]
  for ($i = 0; $i -lt $MaxLines; $i++) {
    $line = $Reader.ReadLine()
    if ($null -eq $line) { break }
    $out.Add($line)
    if ($line.StartsWith($Tag + ' ')) { break }
  }
  return $out
}

# 真实 IMAP 客户端：连 993（隐式 TLS）→ LOGIN → SELECT INBOX → UID SEARCH ALL
function Test-ImapLogin {
  param([string]$Email, [string]$Password)
  $res = @{ Ok = $false; Detail = ''; Count = -1; Select = '' }
  $tcp = New-Object Net.Sockets.TcpClient
  try {
    $tcp.Connect($ImapHost, $ImapPort)
    $tcp.ReceiveTimeout = 20000
    $cb = [Net.Security.RemoteCertificateValidationCallback] { param($a, $b, $c, $d) return $true }
    $ssl = New-Object Net.Security.SslStream($tcp.GetStream(), $false, $cb)
    $ssl.AuthenticateAsClient($ImapName)
    $reader = New-Object IO.StreamReader($ssl, [Text.Encoding]::UTF8)
    $writerEncoding = New-Object Text.UTF8Encoding($false)
    $writer = New-Object IO.StreamWriter($ssl, $writerEncoding)
    $writer.NewLine = "`r`n"
    $writer.AutoFlush = $true

    $greeting = $reader.ReadLine()
    if ($greeting -notmatch '^\* OK') { $res.Detail = "问候语异常: $greeting"; return $res }

    $writer.WriteLine("a1 LOGIN $Email $Password")
    $login = Read-ImapUntil $reader 'a1'
    $loginText = ($login -join ' | ')
    if ($loginText -notmatch 'a1 OK') { $res.Detail = "LOGIN 失败: $loginText"; return $res }

    $writer.WriteLine('a2 SELECT INBOX')
    $sel = Read-ImapUntil $reader 'a2'
    $selText = ($sel -join ' ')
    if ($selText -notmatch 'a2 OK') { $res.Detail = "SELECT 失败: $selText"; return $res }

    $exists = 0
    $m = [regex]::Match($selText, '\*\s+(\d+)\s+EXISTS')
    if ($m.Success) { $exists = [int]$m.Groups[1].Value }

    $writer.WriteLine('a3 UID SEARCH ALL')
    $search = Read-ImapUntil $reader 'a3'
    $searchText = ($search -join ' ')
    $uidCount = -1
    $sm = [regex]::Match($searchText, '\*\s+SEARCH([\d\s]*)')
    if ($sm.Success) {
      $ids = ($sm.Groups[1].Value -split '\s+' | Where-Object { $_ -ne '' })
      $uidCount = $ids.Count
    }

    $writer.WriteLine('a4 LOGOUT')
    [void](Read-ImapUntil $reader 'a4')

    $res.Ok = $true
    $res.Count = $uidCount
    $res.Select = "EXISTS=$exists UIDSEARCH=$uidCount"
    return $res
  } catch {
    $res.Detail = $_.Exception.Message
    return $res
  } finally {
    try { $tcp.Close() } catch { }
  }
}

function Set-UserActive {
  param([string]$Token, [string]$Email, [bool]$Active)
  $path = '/api/admin/users/' + [Uri]::EscapeDataString($Email)
  return Invoke-Api 'PATCH' $path @{ active = $Active } $Token
}

# ================================================================ 开始
Say ("WpywMail 账号体系真实验收   {0}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
Say ("目标 API：{0}    IMAP：{1}:{2}" -f $Base, $ImapHost, $ImapPort)
Say ''

# 从服务器自己的配置里取管理员口令与邀请码（不硬编码，避免和部署配置不一致）
$cfg = [System.IO.File]::ReadAllText($AppSettings) | ConvertFrom-Json
$invite = $cfg.Accounts.InviteCode
$adminEmail = $cfg.AdminEmail
$adminPassword = $cfg.AdminPassword
$domain = $cfg.Domain
Say ("配置：域名={0}  邀请码长度={1}  管理员={2}" -f $domain, $invite.Length, $adminEmail)
Say ''

$suffix = (Get-Random -Minimum 100000 -Maximum 999999)
$newEmail = "selftest-$suffix@$domain"
$newPassword = "Selftest-Pass-$suffix"
$resetPassword = "Reset-Pass-$suffix"
$lockEmail = "locktest-$suffix@$domain"
$lockPassword = "Locktest-Pass-$suffix"
$tempAccounts = @($newEmail, $lockEmail)

# 管理员先登录：后面「注册配额用尽」时要靠它兜底建号，最后的管理员用例也复用它
$adminLogin = Invoke-Api 'POST' '/api/login' @{ email = $adminEmail; password = $adminPassword }
$adminToken = Get-Token $adminLogin.Json
Ok 'A0 管理员可以登录' ($adminLogin.Code -eq 200 -and $adminToken.Length -gt 20) ("HTTP " + $adminLogin.Code + " " + [string](Field $adminLogin.Json 'error'))

# ---------------------------------------------------------------- A 策略
$ver = Invoke-Api 'GET' '/api/version'
Ok 'A1 /api/version 可达' ($ver.Code -eq 200) ("HTTP " + $ver.Code)

$pol = Invoke-Api 'GET' '/api/auth/policy'
Ok 'A2 策略接口可达' ($pol.Code -eq 200) ("HTTP " + $pol.Code)
Ok 'A3 注册模式 = invite' ((Field $pol.Json 'registration') -eq 'invite') ([string](Field $pol.Json 'registration'))
Ok 'A4 需要邀请码标记' ((Field $pol.Json 'inviteRequired') -eq $true) ([string](Field $pol.Json 'inviteRequired'))
$allowed = Field $pol.Json 'allowedDomains'
Ok 'A5 允许域名包含本机域' ($allowed -contains $domain) ([string]::Join(',', $allowed))
Ok 'A6 密码最短长度 >= 8' (([int](Field $pol.Json 'minPasswordLength' 0)) -ge 8) ([string](Field $pol.Json 'minPasswordLength'))
$note = [string](Field $pol.Json 'verificationNote' '')
Ok 'A7 策略里说明了「本机托管地址免验证」的原因' ($note.Length -gt 10) $note

# ---------------------------------------------------------------- B/C 注册
$badInvite = Invoke-Api 'POST' '/api/register' @{
  email = $newEmail; password = $newPassword; displayName = '验收账号'; inviteCode = 'WRONG-CODE'
}
Ok 'B1 邀请码错误被拒（403）' ($badInvite.Code -eq 403) ([string](Field $badInvite.Json 'error'))

$badDomain = Invoke-Api 'POST' '/api/register' @{
  email = "nobody-$suffix@example.com"; password = $newPassword; displayName = '外部域'; inviteCode = $invite
}
Ok 'B2 白名单外的域名被拒（400）' ($badDomain.Code -eq 400) ([string](Field $badDomain.Json 'error'))

$weak = Invoke-Api 'POST' '/api/register' @{
  email = $newEmail; password = '12345678'; displayName = '弱密码'; inviteCode = $invite
}
Ok 'B3 弱密码被拒（400）' ($weak.Code -eq 400) ([string](Field $weak.Json 'error'))

$reg = Invoke-Api 'POST' '/api/register' @{
  email = $newEmail; password = $newPassword; displayName = '验收账号'; inviteCode = $invite
}
$session = Field $reg.Json 'session'
$token = [string](Field $session 'token' '')
if ($reg.Code -eq 429) {
  # 一小时内重复跑本脚本会撞到 IP 配额（配额按「真的建出的账号数」计，见 AccountService）。
  # 这不是缺陷，但要如实标注，并改用管理员接口建号，让后面的 40 多项用例照常跑完。
  Skip 'C1/C2/C3 自助注册链路' '本小时该 IP 的注册配额已用尽（重复运行脚本所致）；已改用管理员接口建号继续验收'
  $boot = Invoke-Api 'POST' '/api/admin/users' @{ email = $newEmail; password = $newPassword; displayName = '验收账号' } $adminToken
  Ok 'C1b 配额用尽时管理员接口可以建号' ($boot.Code -eq 201) ("HTTP " + $boot.Code + " " + [string](Field $boot.Json 'error'))
  $boot2 = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = $newPassword }
  $token = Get-Token $boot2.Json
  Ok 'C1c 兜底建的号可以登录' ($boot2.Code -eq 200 -and $token.Length -gt 20) ("HTTP " + $boot2.Code)
} else {
  Ok 'C1 本机域注册成功（201）' ($reg.Code -eq 201) ("HTTP " + $reg.Code + " " + [string](Field $reg.Json 'error'))
  Ok 'C2 本机域注册不需要邮箱验证（死循环回归）' ((Field $reg.Json 'verificationRequired') -eq $false) ([string](Field $reg.Json 'verificationRequired'))
  Ok 'C3 注册直接返回会话 token' ($token.Length -gt 20) ("token 长度 " + $token.Length)
}

$me = Invoke-Api 'GET' '/api/me' $null $token
Ok 'C4 注册后的 token 可访问 /api/me' ($me.Code -eq 200) ("HTTP " + $me.Code)
Ok 'C5 /api/me 返回的账号一致' (([string](Field (Field $me.Json 'user') 'email' '')) -eq $newEmail) ([string](Field (Field $me.Json 'user') 'email' ''))

$login1 = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = $newPassword }
$token2 = Get-Token $login1.Json
Ok 'C6 新账号可以正常登录' ($login1.Code -eq 200 -and $token2.Length -gt 20) ("HTTP " + $login1.Code)
if (-not $token) { $token = $token2 }

# ---------------------------------------------------------------- D 会话 / 资料 / 审计
$prof = Invoke-Api 'PATCH' '/api/account/profile' @{ displayName = "验收账号-$suffix" } $token
Ok 'D1 修改显示名成功' ($prof.Code -eq 200) ([string](Field $prof.Json 'error'))
$me2 = Invoke-Api 'GET' '/api/me' $null $token
Ok 'D2 显示名已生效' (([string](Field (Field $me2.Json 'user') 'displayName' '')) -eq "验收账号-$suffix") ([string](Field (Field $me2.Json 'user') 'displayName' ''))

$sess = Invoke-Api 'GET' '/api/account/sessions' $null $token
$sessList = Field $sess.Json 'sessions'
Ok 'D3 会话列表可读且包含当前会话' ($sess.Code -eq 200 -and $null -ne ($sessList | Where-Object { (Field $_ 'current') -eq $true })) ("共 " + @($sessList).Count + " 个会话")

$audit = Invoke-Api 'GET' '/api/account/audit?limit=50' $null $token
$events = Field $audit.Json 'events'
$reasons = @($events | ForEach-Object { [string](Field $_ 'reason' '') })
Ok 'D4 审计里能看到 register 事件' ($reasons -contains 'register') ([string]::Join(',', $reasons))
Ok 'D5 审计里能看到 login-ok 事件' ($reasons -contains 'login-ok') ''
Ok 'D6 审计里能看到 profile-updated 事件' ($reasons -contains 'profile-updated') ''

# ---------------------------------------------------------------- E 真实 IMAP
$imap = Test-ImapLogin $newEmail $newPassword
Ok 'E1 新账号能用真实 IMAP(993 隐式 TLS) 登录' $imap.Ok ([string]$imap.Detail)
Ok 'E2 IMAP SELECT INBOX 成功' ($imap.Ok -and $imap.Select -ne '') ([string]$imap.Select)

# 自己给自己发一封中文邮件，验证本地投递进了这个新信箱
$send = Invoke-Api 'POST' '/api/send' @{
  to = $newEmail; subject = "账号验收邮件 $suffix"; text = "这封邮件用来验证新注册账号的信箱能收信。编号 $suffix"
} $token
Ok 'E3 新账号可以发信（入队 202）' ($send.Code -eq 202) ("HTTP " + $send.Code + " " + [string](Field $send.Json 'error'))

$landed = Wait-InboxMessage $token "账号验收邮件*" 40
$landedId = [string](Field $landed 'id' '')
Ok 'E4 自己发的邮件已投递进收件箱' ($null -ne $landed -and $landedId.Length -gt 0) ([string](Field $landed 'subject' '(未收到)'))

$imap2 = Test-ImapLogin $newEmail $newPassword
Ok 'E5 IMAP 收件箱计数 >= 1' ($imap2.Ok -and $imap2.Count -ge 1) ([string]$imap2.Select)

# ---------------------------------------------------------------- F 忘记密码 → 读信取码 → 重置
$forgot = Invoke-Api 'POST' '/api/auth/forgot' @{ email = $newEmail }
Ok 'F1 申请重置密码返回成功' ($forgot.Code -eq 200) ("HTTP " + $forgot.Code + " " + [string](Field $forgot.Json 'error'))

$resetMail = Wait-InboxMessage $token '*重置密码验证码*' 40
$resetId = [string](Field $resetMail 'id' '')
Ok 'F2 重置验证码邮件已投进收件箱' ($resetId.Length -gt 0) ([string](Field $resetMail 'subject' '(未收到)'))

$code = ''
if ($resetId) {
  $detail = Invoke-Api 'GET' ("/api/messages/" + [Uri]::EscapeDataString($resetId)) $null $token
  $msg = Field $detail.Json 'message'
  $body = [string](Field $msg 'text' '')
  if (-not $body) { $body = [string](Field $msg 'html' '') }
  # ⚠ 必须锚定「验证码：」这个标签：邮件正文里还写着收件人地址（selftest-123456@…），
  #   直接抓第一个 6 位数字会抓到地址里的数字，测试自己就成了假失败源。
  $cm = [regex]::Match($body, '验证码[：:]\s*(\d{6})')
  if (-not $cm.Success) {
    $all = [regex]::Matches($body, '\b(\d{6})\b')
    if ($all.Count -gt 0) { $cm = $all[$all.Count - 1] }
  }
  if ($cm.Success) {
    if ($cm.Groups.Count -gt 1) { $code = $cm.Groups[1].Value } else { $code = $cm.Value }
  }
}
Ok 'F3 能从邮件正文里取出 6 位验证码' ($code.Length -eq 6) ("code=" + $(if ($code) { $code } else { '(空)' }))

$badReset = Invoke-Api 'POST' '/api/auth/reset' @{ email = $newEmail; code = '000000'; password = $resetPassword }
Ok 'F4 错误验证码被拒（400）' ($badReset.Code -eq 400) ([string](Field $badReset.Json 'error'))

if ($code.Length -eq 6) {
  $goodReset = Invoke-Api 'POST' '/api/auth/reset' @{ email = $newEmail; code = $code; password = $resetPassword }
  Ok 'F5 正确验证码重置成功' ($goodReset.Code -eq 200) ("HTTP " + $goodReset.Code + " " + [string](Field $goodReset.Json 'error'))
}

$oldLogin = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = $newPassword }
Ok 'F6 重置后旧密码失效（401）' ($oldLogin.Code -eq 401) ("HTTP " + $oldLogin.Code)
$newLogin = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = $resetPassword }
$token3 = Get-Token $newLogin.Json
Ok 'F7 重置后新密码可登录' ($newLogin.Code -eq 200 -and $token3.Length -gt 20) ("HTTP " + $newLogin.Code)
$imap3 = Test-ImapLogin $newEmail $resetPassword
Ok 'F8 新密码同样能用 IMAP 登录' $imap3.Ok ([string]$imap3.Detail)

if ($token3) { $token = $token3 }

# ---------------------------------------------------------------- G 改密踢掉其他会话
$loginExtra = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = $resetPassword }
$token4 = Get-Token $loginExtra.Json
$before = @(Field (Invoke-Api 'GET' '/api/account/sessions' $null $token).Json 'sessions').Count
$changed = Invoke-Api 'POST' '/api/account/password' @{ currentPassword = $resetPassword; password = $newPassword } $token
$after = @(Field (Invoke-Api 'GET' '/api/account/sessions' $null $token).Json 'sessions').Count
Ok 'G1 修改密码成功' ($changed.Code -eq 200) ("HTTP " + $changed.Code + " " + [string](Field $changed.Json 'error'))
Ok 'G2 改密后其他会话被吊销（当前保留）' ($after -lt $before -and $after -ge 1) ("改前 $before → 改后 $after")
if ($token4) {
  $stale = Invoke-Api 'GET' '/api/me' $null $token4
  Ok 'G3 被踢掉的那个 token 已失效（401）' ($stale.Code -eq 401) ("HTTP " + $stale.Code)
}

# ---------------------------------------------------------------- H 登录失败锁定
$lockReg = Invoke-Api 'POST' '/api/register' @{
  email = $lockEmail; password = $lockPassword; displayName = '锁定验收'; inviteCode = $invite
}
if ($lockReg.Code -eq 429) {
  Skip 'H1 第二个测试账号自助注册' '本小时注册配额已用尽（重复运行脚本所致）；改用管理员接口建号'
  $lockReg = Invoke-Api 'POST' '/api/admin/users' @{ email = $lockEmail; password = $lockPassword; displayName = '锁定验收' } $adminToken
}
Ok 'H1 第二个测试账号建号成功' ($lockReg.Code -eq 201) ("HTTP " + $lockReg.Code + " " + [string](Field $lockReg.Json 'error'))

$maxFail = [int](Field $pol.Json 'maxLoginFailures' 8)
$lastCode = 0
for ($i = 1; $i -le ($maxFail + 1); $i++) {
  $r = Invoke-Api 'POST' '/api/login' @{ email = $lockEmail; password = "Wrong-Password-$i" }
  $lastCode = $r.Code
}
$lockReply = Invoke-Api 'POST' '/api/login' @{ email = $lockEmail; password = $lockPassword }
$retryAfter = Field $lockReply.Json 'retryAfterSeconds'
Ok 'H2 连续失败后返回 423 锁定' ($lockReply.Code -eq 423) ("HTTP " + $lockReply.Code + " " + [string](Field $lockReply.Json 'error'))
Ok 'H3 锁定响应带 retryAfterSeconds' (($null -ne $retryAfter) -and ([int]$retryAfter -gt 0)) ("retryAfterSeconds=" + [string]$retryAfter + " 原始响应: " + $lockReply.Raw)
Ok 'H4 锁定期间即使密码正确也被挡（不泄露密码对错）' ($lockReply.Code -eq 423) ''

# ---------------------------------------------------------------- I 管理员视角
$users = Invoke-Api 'GET' '/api/admin/users' $null $adminToken
$userList = Field $users.Json 'users'
$mine = $userList | Where-Object { ([string](Field $_ 'email' '')) -eq $newEmail }
Ok 'I2 管理员能看到新注册的账号' ($null -ne $mine) ("共 " + @($userList).Count + " 个账号")
Ok 'I3 新账号在管理员视角是启用状态' ($null -ne $mine -and (Field $mine 'active') -eq $true) ([string](Field $mine 'active'))

$adminAudit = Invoke-Api 'GET' '/api/admin/audit?limit=50' $null $adminToken
$adminEvents = Field $adminAudit.Json 'events'
$adminReasons = @($adminEvents | ForEach-Object { [string](Field $_ 'reason' '') })
Ok 'I4 管理员能看到全站审计' ($adminAudit.Code -eq 200 -and $adminEvents.Count -gt 0) ("共 " + @($adminEvents).Count + " 条，含 " + [string]::Join('/', ($adminReasons | Select-Object -Unique -First 6)))

$nonAdmin = Invoke-Api 'GET' '/api/admin/users' $null $token
Ok 'I5 普通账号访问管理接口被拒（403）' ($nonAdmin.Code -eq 403) ("HTTP " + $nonAdmin.Code)

# ---------------------------------------------------------------- J 停用 + 清理
$deact = Set-UserActive $adminToken $lockEmail $false
Ok 'J1 管理员可停用账号' ($deact.Code -eq 200) ("HTTP " + $deact.Code + " " + [string](Field $deact.Json 'error'))
$deact2 = Set-UserActive $adminToken $newEmail $false
Ok 'J2 清理：停用验收账号一' ($deact2.Code -eq 200) ("HTTP " + $deact2.Code)

$disabled = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = $newPassword }
Ok 'J3 被停用的账号不能登录（401，且不暴露账号状态）' ($disabled.Code -eq 401) ("HTTP " + $disabled.Code + " " + [string](Field $disabled.Json 'error'))
$disabledImap = Test-ImapLogin $newEmail $newPassword
Ok 'J4 被停用的账号不能登录 IMAP' (-not $disabledImap.Ok) ([string]$disabledImap.Detail)

# 停用必须是权威状态：不能靠「重新注册」把封禁翻回来（这是真机验收抓出来的洞）
$revive = Invoke-Api 'POST' '/api/register' @{
  email = $newEmail; password = "Revive-Pass-$suffix"; displayName = '尝试复活'; inviteCode = $invite
}
Ok 'J5 被停用的账号不能靠重新注册复活（403）' ($revive.Code -eq 403) ("HTTP " + $revive.Code + " " + [string](Field $revive.Json 'error'))
$stillDisabled = Invoke-Api 'POST' '/api/login' @{ email = $newEmail; password = "Revive-Pass-$suffix" }
Ok 'J6 复活尝试后账号依然进不去（401）' ($stillDisabled.Code -eq 401) ("HTTP " + $stillDisabled.Code)

Say ''
Say ("=== 结果：{0} 项通过，{1} 项失败，{2} 项跳过 ===" -f $script:pass, $script:fail, $script:skip)
Say ''
Say "说明：测试期间创建的两个账号已停用（不是删除，服务器暂无删除账号接口）："
foreach ($a in $tempAccounts) { Say ("  - {0}" -f $a) }

try {
  $utf8 = New-Object Text.UTF8Encoding($true)
  [System.IO.File]::WriteAllLines($Report, $script:logLines, $utf8)
  Write-Host ("报告已写入 {0}" -f $Report)
} catch {
  Write-Host ("报告写入失败：{0}" -f $_.Exception.Message)
}

exit $script:fail
