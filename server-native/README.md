# wpyw.mail Windows 邮箱服务

这是一个不依赖 Node、npm、数据库或第三方运行库的 Windows 原生服务端。安装包会自动配置：

- 邮箱：`wpy@wpyw.site`
- 收信：SMTP 25
- 客户端发信：SMTP Submission 587
- 客户端接口：本机 `127.0.0.1:8787`
- 文件存储、收件箱、已发送、发送队列和失败重试
- STARTTLS（需要 `mail.wpyw.site` 的 PFX 证书）

## 一、最简单的安装方式

1. 在 Windows Server 2022 上以管理员身份运行 `wpyw-mail-server-installer.exe`。
2. 安装器出现中文问题时，按下面的规则填写：

   | 安装器问题 | 应填写什么 | 第一次安装建议 |
   | --- | --- | --- |
   | 程序安装目录 | 服务程序放在哪里 | 直接回车 |
   | 邮件数据目录 | 邮件和账户数据长期保存在哪里 | 磁盘空间充足时填 `D:\WpywMailData`，没有 D 盘就直接回车 |
   | 邮箱密码 | `wpy@wpyw.site` 的登录密码 | 输入至少 12 位强密码，输入时屏幕不会显示 |
   | SMTP 外发中继服务器 | 用来把邮件发到公网的 SMTP 服务器 | 没有就直接回车，使用 MX 直投 |
   | SMTP 外发中继端口 | 中继服务器端口 | 只有填写中继服务器后才出现，默认 587 |
   | SMTP 中继账号 | 中继账号 | 只有填写中继服务器后才出现 |
   | SMTP 中继密码 | 中继密码 | 只有填写中继账号后才出现 |
   | PFX 证书路径 | `mail.wpyw.site` 的证书文件路径 | 没有就直接回车，安装器会生成临时证书 |
   | PFX 证书密码 | PFX 文件密码 | 没密码就直接回车 |

3. 安装器会创建 Windows 防火墙规则、注册开机启动任务并启动服务。
4. 安装完成后，记录安装器显示的邮箱地址和数据目录。

## 二、第一次安装可以直接这样填

如果你暂时没有 SMTP 中继，也没有正式 PFX 证书：

```text
程序安装目录：直接回车
邮件数据目录：直接回车
邮箱密码：输入你自己设置的至少 12 位密码
SMTP 外发中继服务器：直接回车
SMTP 外发中继端口：不会出现
SMTP 中继账号：不会出现
SMTP 中继密码：不会出现
PFX 证书路径：直接回车
PFX 证书密码：不会出现，或直接回车
```

不填写 SMTP 中继时，服务端会使用 MX 直投：查询收件人域名的 MX 记录，再连接对方 25 端口发送。你已经确认服务器可以连接 QQ MX 的 25 端口。

## 三、Cloudflare DNS 保持这样

```text
mail.wpyw.site  A    <SERVER_IP>    DNS only
wpyw.site       MX   mail.wpyw.site   DNS only
```

网站或未来 WinUI 客户端的 Web/API 路由可以通过 Cloudflare Tunnel 指向：

```text
http://127.0.0.1:8787/
```

SMTP 25 和 587 不要放到普通 HTTP Tunnel 路由里；它们应直接连接 `mail.wpyw.site`，并在服务器和云主机防火墙中开放。

## 四、当前版本的边界

当前服务端还没有 IMAP/POP3、DKIM 签名和完整反垃圾系统，因此第一版 WinUI 客户端通过 REST API 工作，Outlook/手机暂时不能直接用 IMAP 登录。MX 直投能工作不代表所有服务商都会接受邮件；正式公网使用还应补齐 DKIM、DMARC、反向 DNS 和退信处理。

## 五、手工启动和查看

安装器默认注册的任务名是 `WpywMail`。管理员 PowerShell 中可以查看：

```powershell
Get-ScheduledTask -TaskName WpywMail
Get-NetFirewallRule -DisplayName 'wpyw.mail SMTP 邮件端口'
```

服务数据在安装时填写的数据目录中；不要删除其中的 `users.json`、`messages.json` 和 `queue.json`。
