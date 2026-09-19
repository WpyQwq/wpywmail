# wpyw.mail

服务端和客户端分离。当前优先维护独立服务端，服务端代码和启动说明位于 [`server/`](H:/Codex/2026-09-08/windows-wpyw-site-cf-web-4/server/)。

服务端提供 SMTP 收信、SMTP Submission 发信、本地邮件存储和 REST API；客户端后续单独开发，不参与服务端启动。

## 启动

```powershell
npm install
Copy-Item .env.example .env
notepad .env
npm run dev
```

开发时访问 `http://localhost:5173`，生产构建后运行：

```powershell
npm run build
npm start
```

默认 Web API 监听 `8787`，SMTP 监听 `25`，Submission 监听 `587`。

## 重要配置

至少修改 `.env` 中的：

```dotenv
MAIL_USER=admin@wpyw.site
MAIL_PASSWORD=一个足够长的密码
MAIL_DATA_DIR=H:\\MailData
```

如果服务器不能直接连接外部 MX 的 25 端口，可以配置 SMTP 中继：

```dotenv
SMTP_RELAY_HOST=smtp.example.com
SMTP_RELAY_PORT=587
SMTP_RELAY_USER=your-user
SMTP_RELAY_PASSWORD=your-password
SMTP_RELAY_SECURE=false
```

## Cloudflare Tunnel

不要把 SMTP 或 IMAP 通过现有 Web Tunnel 暴露给普通客户端。建议增加单独的 Webmail hostname：

```yaml
ingress:
  - hostname: webmail.wpyw.site
    service: http://127.0.0.1:5173
  - service: http_status:404
```

`mail.wpyw.site` 保持 DNS only，继续直接指向邮件服务器公网 IP。MX 记录继续指向 `mail.wpyw.site`。

## 当前版本边界

这是一个可运行的单账户基础服务，不等同于成熟商业邮件系统。正式长期运行前，还应增加 DKIM 签名、DMARC 报告、反垃圾策略、速率限制、持久化会话、多账户管理、附件下载鉴权、备份和监控。不要把它配置成 Open Relay。
