# wpyw.mail server

这是独立的邮箱服务端，不包含任何 Webmail 客户端代码。

当前服务端提供：

- SMTP 25：接收发往 `@wpyw.site` 的邮件
- SMTP Submission 587：登录认证后发信
- REST API：供未来独立客户端使用
- 本地 JSON 邮件存储和附件落盘
- 可选外部 SMTP 中继

## 启动

在 `server/` 目录执行：

```powershell
npm install
Copy-Item .env.example .env
notepad .env
npm start
```

必须设置 `MAIL_PASSWORD`，服务端不会使用默认密码启动。

默认监听：

```text
REST API       8787
SMTP           25
SMTP Submission 587
```

测试时可以临时改成非特权端口：

```powershell
$env:WEB_PORT='8787'
$env:SMTP_PORT='2525'
$env:SUBMISSION_PORT='2587'
npm start
```

## API

登录：

```http
POST /api/login
Content-Type: application/json

{"email":"admin@wpyw.site","password":"你的密码"}
```

之后把返回的 token 放入请求头：

```http
Authorization: Bearer <token>
```

主要接口：

```text
GET  /api/health
GET  /api/config
GET  /api/me
GET  /api/messages?folder=inbox
GET  /api/messages/:id
POST /api/send
POST /api/logout
```

发信请求示例：

```json
{
  "to": "someone@example.com",
  "subject": "测试邮件",
  "text": "邮件正文"
}
```

## Cloudflare 和端口

`mail.wpyw.site` 应保持 DNS only，MX 指向 `mail.wpyw.site`。网站或未来的 Webmail 客户端可以继续通过 Cloudflare Tunnel，但 SMTP 25/587 直接连接服务器公网 IP。

## 当前边界

这是第一版服务端：已经具备收信、发信和客户端 API，但还没有实现 IMAP/POP3、多用户、DKIM 签名、DMARC 报告、反垃圾、配额和管理后台。未来客户端应通过 REST API 或后续增加的 IMAP 服务访问邮箱。

不要把它配置成 Open Relay。正式公网使用前，应配置 `mail.wpyw.site` 的 TLS 证书、PTR 反向解析、SPF、DKIM、DMARC，并优先考虑 SMTP 中继以提高投递率。

当前没有监听 993/995，因此暂时不要把它当作 Outlook/手机的 IMAP/POP3 服务器使用；第一版客户端应通过 REST API 连接。
