<#
.SYNOPSIS
  把 WpywMail 需要的 DKIM / DMARC 记录写入 Cloudflare（一条命令补完 DNS）。

.DESCRIPTION
  记录值直接由服务端二进制从 DKIM 私钥推导（--dkim-dns），避免手工复制出错。
  幂等：已存在的同名记录会被更新而不是重复创建。

.EXAMPLE
  # 在本机执行（会通过 WinRM 读取服务器上的公钥）
  .\publish-dns.ps1 -Server <SERVER_IP> -Zone wpy.email -ApiToken "<CF Token>"

.NOTES
  Token 需要权限：Zone:DNS:Edit（对该 zone）。
  也可先只看将要写入的内容而不实际提交：加上 -WhatIfOnly
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Server,
    [Parameter(Mandatory)][string]$Zone,
    [Parameter(Mandatory)][string]$ApiToken,
    [string]$RemoteUser = 'Administrator',
    [string]$RemotePassword,
    [string]$RemoteExe = 'C:\Program Files\WpywMail\WpywMail.Native.exe',
    [string]$DmarcPolicy = 'p=none',
    [switch]$WhatIfOnly
)

$ErrorActionPreference = 'Stop'

function Invoke-Cf {
    param([string]$Method, [string]$Path, $Body)
    $uri = "https://api.cloudflare.com/client/v4$Path"
    $headers = @{ Authorization = "Bearer $ApiToken"; 'Content-Type' = 'application/json' }
    if ($Body) {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers -Body ($Body | ConvertTo-Json -Depth 8)
    } else {
        Invoke-RestMethod -Method $Method -Uri $uri -Headers $headers
    }
}

# ---------- 1) 从服务器取回需要写入的记录 ----------
Write-Host '正在从服务器读取 DKIM 公钥…' -ForegroundColor Cyan
if ($RemotePassword) {
    $sec = ConvertTo-SecureString $RemotePassword -AsPlainText -Force
    $cred = New-Object System.Management.Automation.PSCredential("$Server\$RemoteUser", $sec)
    $lines = Invoke-Command -ComputerName $Server -Credential $cred -ScriptBlock {
        param($exe) & $exe --dkim-dns
    } -ArgumentList $RemoteExe
} else {
    $lines = Invoke-Command -ComputerName $Server -ScriptBlock {
        param($exe) & $exe --dkim-dns
    } -ArgumentList $RemoteExe
}

$map = @{}
foreach ($line in $lines) {
    if ($line -match '^([A-Z_]+)=(.*)$') { $map[$Matches[1]] = $Matches[2] }
}
if (-not $map['NAME'] -or -not $map['VALUE']) { throw "未能从服务器取得 DKIM 记录（输出：`n$($lines -join "`n")）" }

$dmarcShortName = $map['DMARC_NAME'] -replace "\.$([regex]::Escape($Zone))$", ''
$dmarcValue = $map['DMARC_VALUE'] -replace 'p=none', $DmarcPolicy

$records = @(
    @{ Type = 'TXT'; Name = $map['NAME']; Content = $map['VALUE'];   Comment = 'WpywMail DKIM' },
    @{ Type = 'TXT'; Name = $dmarcShortName; Content = $dmarcValue;  Comment = 'WpywMail DMARC' }
)

Write-Host "`n将写入以下记录（zone=$Zone）：" -ForegroundColor Cyan
foreach ($r in $records) {
    Write-Host ("  {0,-4} {1,-28} {2}" -f $r.Type, $r.Name, ($r.Content.Substring(0, [Math]::Min(80, $r.Content.Length)) + $(if ($r.Content.Length -gt 80) { '…' } else { '' })))
}
if ($WhatIfOnly) { Write-Host "`n-WhatIfOnly：未提交任何更改。" -ForegroundColor Yellow; return }

# ---------- 2) 解析 zone id ----------
$zones = Invoke-Cf -Method GET -Path "/zones?name=$Zone"
if (-not $zones.result -or $zones.result.Count -eq 0) { throw "Cloudflare 中找不到 zone：$Zone（检查 Token 权限与域名拼写）" }
$zoneId = $zones.result[0].id
Write-Host "`nzone id: $zoneId" -ForegroundColor DarkGray

# ---------- 3) 幂等写入 ----------
foreach ($r in $records) {
    $fqdn = if ($r.Name) { "$($r.Name).$Zone" } else { $Zone }
    $existing = Invoke-Cf -Method GET -Path "/zones/$zoneId/dns_records?type=$($r.Type)&name=$fqdn"
    $payload = @{ type = $r.Type; name = $fqdn; content = $r.Content; ttl = 1; comment = $r.Comment }

    if ($existing.result.Count -gt 0) {
        $id = $existing.result[0].id
        $null = Invoke-Cf -Method PUT -Path "/zones/$zoneId/dns_records/$id" -Body $payload
        Write-Host "  [更新] $fqdn" -ForegroundColor Yellow
    } else {
        $null = Invoke-Cf -Method POST -Path "/zones/$zoneId/dns_records" -Body $payload
        Write-Host "  [新建] $fqdn" -ForegroundColor Green
    }
}

Write-Host "`n完成。等 1-2 分钟后可用以下命令核验：" -ForegroundColor Cyan
Write-Host "  Resolve-DnsName $($map['NAME']).$Zone -Type TXT -Server 1.1.1.1"
Write-Host "  Resolve-DnsName _dmarc.$Zone -Type TXT -Server 1.1.1.1"
