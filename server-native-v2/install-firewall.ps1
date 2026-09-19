New-NetFirewallRule -DisplayName 'wpyw.mail SMTP 邮件端口' -Direction Inbound -Protocol TCP -LocalPort 25,587 -Action Allow
# API 8787 默认只监听本机，再通过 Cloudflare Tunnel 暴露 Web/API。
# 如需让独立客户端直连，请先评估安全策略后再单独开放 8787。
