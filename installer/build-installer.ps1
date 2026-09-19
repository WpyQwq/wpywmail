$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$native = Join-Path $root 'server-native'
$stage = Join-Path $root ("work\installer-stage-" + (Get-Date -Format 'yyyyMMddHHmmss'))
$payload = Join-Path $stage 'payload'
$publish = Join-Path $stage 'publish'
$outputDir = Join-Path $root 'outputs'
$bootstrap = Join-Path $root 'installer-bootstrap'
$payloadZip = Join-Path $bootstrap 'Payload.zip'
$installerPublish = Join-Path $stage 'installer-publish'
$target = Join-Path $outputDir 'wpyw-mail-server-installer.exe'

New-Item -ItemType Directory -Force -Path $payload, $outputDir | Out-Null

dotnet publish (Join-Path $native 'WpywMail.Native.csproj') -c Release -r win-x64 --self-contained true -o $publish
Copy-Item -Path (Join-Path $publish '*') -Destination $payload -Recurse -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install.cmd') -Destination $payload -Force
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'install.ps1') -Destination $payload -Force

Compress-Archive -Path (Join-Path $payload '*') -DestinationPath $payloadZip -CompressionLevel Optimal -Force

dotnet publish (Join-Path $bootstrap 'Installer.csproj') -c Release -r win-x64 --self-contained true -o $installerPublish
Copy-Item -LiteralPath (Join-Path $installerPublish 'wpyw-mail-server-installer.exe') -Destination $target -Force
Write-Host "安装包已生成：$target"
