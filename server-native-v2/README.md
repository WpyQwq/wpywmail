# WpywMail.Native v2

自建中文邮件服务（Windows / .NET 8，单文件进程，零外部依赖）。
本目录是 v2 重写版本；v1 原样保留在 `../server-native`，部署现场备份在 `C:\Program Files\WpywMail.v1-backup`。

---

## 1. 它做什么

```
                     ┌──────────────── WpywMail.Native.exe ────────────────┐
   公网 25 ─────────►│ SmtpServer  收信（只收本地收件人，绝不中继）          │
   客户端 587 ──────►│ SmtpServer  发信（STARTTLS + AUTH 后提交）           │
   Webmail/客户端 ──►│ ApiServer   REST + 长轮询（默认仅监听 127.0.0.1）     │
                     │ DeliveryQueue  出站队列：DKIM 签名 → MX 直投/中继    │
                     │ FileStore  users/messages/queue/sessions + raw/     │
                     └────────────────────────────────────────────────────┘
```

| 文件 | 职责 |
|---|---|
| `Program.cs` | 入口、配置校验、启动/停止、`--selftest` / `--check-config` / `--migrate` |
| `Models.cs` | 配置与数据模型 |
| `Mime.cs` | MIME 组装与解析（RFC 5322 / 2047 / 2231、base64、QP、multipart、附件、字符集） |
| `Dkim.cs` | DKIM 签名（RFC 6376，rsa-sha256，relaxed/relaxed，自动生成密钥并打印 DNS 记录） |
| `SmtpServer.cs` | 25 收信 / 587 提交服务端 |
| `SmtpReader.cs` | 字节级 SMTP 行读取器（命令与 DATA 共用缓冲区，保证 8bit 正文不被破坏） |
| `SmtpDataEncoder.cs` | DATA 段编码/还原（行尾规范化、dot-stuffing），与 DKIM 签名顺序严格配合 |
| `DirectSmtpDelivery.cs` | 出站投递（MX 直投 / relay 中继）+ 极简 DNS MX 解析 |
| `DeliveryQueue.cs` | 出站队列：重试、退避、退信通知 |
| `FileStore.cs` | 文件存储与全部状态变更 |
| `ApiServer.cs` | REST API（Webmail 与桌面客户端共用） |
| `Migration.cs` | 从 v1 数据一次性迁移/修复 |

---

## 2. v1 的问题与本版修法

| # | v1 问题（位置） | 后果 | v2 处理 |
|---|---|---|---|
| 1 | `DirectSmtpDelivery.cs:192` 用 `Encoding.ASCII` 的 StreamWriter 写 DATA | **所有非 ASCII 变 `?`**，中文彻底不可用 | 按字节写出；`SmtpDataEncoder` 只做 dot-stuffing |
| 2 | `Mime.cs:28` 写死 `Message-ID: <...@wpyw.site>` | 声明域 ≠ 发信域，垃圾邮件特征 | 取配置 `Domain` |
| 3 | `Mime.Parse` 不解码 RFC 2047、不解 base64/QP 正文 | 收件显示 `=?utf-8?b?...?=`、正文乱码 | 完整解码（含量化可打印、软换行合并） |
| 4 | 头部按 Latin-1 解码 | 裸 UTF-8 主题变 `[æµè¯]` | UTF-8 优先、失败回退 Latin-1 |
| 5 | `SmtpServer.ReadData` 用 StreamReader 读文本再拼回 | 8bit 内容/行尾被破坏、O(n²) 长度统计、无上限 | 字节级读取 + 大小上限 + dot-unstuffing |
| 6 | 自签名证书时不广告 STARTTLS，但 AUTH 又要求加密 | **587 完全死锁（538）** | 只要加载到证书就广告 STARTTLS；AUTH 在 TLS 后提供 |
| 7 | 无 DKIM | 进垃圾箱 | 新增 DKIM 签名（含密钥生成与 DNS 记录输出） |
| 8 | 4xx/5xx 一律按 8 次封顶，无退信 | 封锁类 5xx 直接丢信且无通知 | 可配置重试策略 + 彻底失败发退信 |
| 9 | 无 multipart / 无附件 | 前端已在读 `attachments` 但后端没有 | 完整 multipart 收/发 + 附件存储与下载 |
| 10 | 会话仅存内存 | 每次重启把客户端踢下线 | 会话落盘 `sessions.json` |
| 11 | 无文件夹/星标/删除/队列接口 | 客户端只能读收件箱 | 补齐（见第 6 节） |
| 12 | 签名后才改行尾 | DKIM 正文哈希对不上，签名失效 | **先规范化 → 再签名 → 传输不改字节**（自检覆盖） |

### 2.1 v2.0.0 自身的 DKIM 缺陷（2026-09-13 由外部验证器揪出，v2.0.1 修复）

| # | 问题（位置） | 后果 | 修法 |
|---|---|---|---|
| 13 | `Dkim.cs` 构造签名输入时，把 `DKIM-Signature` 头放在**最前面**且**多带一个结尾 CRLF** | 违反 RFC 6376 §3.7 第 2 步 → **Gmail / Outlook / port25 等所有合规验证器一律判 `dkim=fail`**，等于白签 | 改为：各被签名头按 `h=` 顺序、每个后跟一个 CRLF；`DKIM-Signature` 头**放最后且结尾不带 CRLF** |

**这条为什么差点被漏掉（重要教训）**：v2.0.0 的 `SelfTest.VerifyDkim` 与本机 Python 验签脚本
当初都是**照着签名端的实现写的**，两边犯了同一个错，于是自检 38/38、加上手写验签脚本全部"通过"——
属于典型的**假通过**。真正把它暴露出来的是**外部独立验证器**（把信发给
`check-auth@verifier.port25.com`，报告里明确写着 `dkim=fail reason="signature doesn't verify"`，
并且它打印的「Canonicalized Headers」里签名头的顺序与我们对不上，一眼看出顺序错误）。

因此本版把「验签」当成**独立实现**来写，并加了两道防线：

1. `SelfTest` 新增**反向对照**用例：故意用非规范顺序（签名头在前 + 带结尾 CRLF）重建签名输入，
   断言它**必须验不过**。若哪天验签器又被写成与签名端"同错"，这项会立刻失败。
2. `tools/verify_published_dkim.py`：只吃 **DNS 上已发布的 TXT**、不接触私钥，
   对真实投递报文按 RFC 6376 顺序验签 —— 直接复现收件方会看到的结果。

修好之后的实测证据（同一把 DNS 公钥、同一个验签器）：

* v2.0.0 签的报文（`14:09` 落盘）→ **失败**（`DigestInfo 不匹配`）
* v2.0.1 签的报文（`14:24` 落盘）→ **通过**
* port25 外部验证器第三次报告 → `DKIM check: pass`，对方写入
  `Authentication-Results: ... dkim=pass (matches From: wpy@wpy.email) header.d=wpy.email`

---

## 3. 配置（appsettings.json）

```jsonc
{
  "Domain": "wpy.email",
  "Hostname": "mail.example.com",
  "HttpPrefix": "http://127.0.0.1:8787/",
  "SmtpPort": 25,
  "SubmissionPort": 587,
  "DataDirectory": "C:\\WpywMailData",
  "AdminEmail": "wpy@wpy.email",
  "AdminPassword": "至少12位；会同步为该账号的登录密码",
  "TlsCertificatePath": "C:\\WpywMailData\\certs\\mail.example.com.pfx",
  "TlsCertificatePassword": "...",
  "DeliveryMode": "direct",              // direct=MX直投 | relay=上游中继

  "Storage": {
    "Provider": "sqlite",                // sqlite（默认，推荐）| json（旧实现，可一键回滚）
    "DatabasePath": "",                  // 留空 = DataDirectory\\wpywmail.db
    "WalAutoCheckpointPages": 0,         // 0 = 用 SQLite 默认（约 1000 页）
    "FullTextSearch": false              // 见第 10 节：打开后搜索快约 20 倍，但索引要占正文量级的空间
  },

  "DirectDelivery": {
    "ConnectionTimeoutSeconds": 30,
    "CommandTimeoutSeconds": 30,
    "DnsTimeoutSeconds": 5,
    "OpportunisticStartTls": true,       // 对方支持就加密，握手失败自动回退明文重连
    "RequireStartTls": false,
    "DnsServer": "",                     // 留空用系统 DNS
    "HeloName": ""                       // 留空用 Hostname
  },

  "Relay": { "Host": "", "Port": 587, "User": "", "Password": "", "EnableSsl": true },

  "Retry": {
    "MaxAttempts": 12,
    "InitialDelaySeconds": 60,
    "MaxDelaySeconds": 3600,
    "RetryOnPermanentFailure": true,     // 5xx 也重试（封锁/策略类常是临时的）
    "MaxAttemptsForPermanent": 3,
    "SendBounceNotification": true       // 彻底失败给发件人发退信
  },

  "Dkim": {
    "Enabled": true,
    "Selector": "mail",                  // DNS 名：mail._domainkey.<Domain>
    "SigningDomain": "",                 // 留空用 Domain
    "PrivateKeyPath": "",                // 留空 = DataDirectory/dkim/<selector>.private.pem
    "Headers": ["From","To","Subject","Date","Message-ID","MIME-Version","Content-Type","Content-Transfer-Encoding"]
  },

  "Api": { "SessionDays": 30, "CorsOrigin": "*", "LongPollSeconds": 25 },

  "Accounts": {
    "Registration": "invite",            // open=自助注册 | invite=需要邀请码 | closed=关闭注册
    "InviteCode": "换成一串只有你知道的随机串",
    "AllowedDomains": ["wpy.email"],     // 允许注册的域名；留空 = 只允许本机域
    "RequireEmailVerification": true,    // ⚠ 本机托管的域名会自动跳过，见第 6.2.2 节
    "MinPasswordLength": 12,
    "CodeMinutes": 30,                   // 验证码有效期
    "MaxCodeAttempts": 5,
    "MaxLoginFailures": 8,               // 连续失败多少次后临时锁定
    "LockoutMinutes": 15,
    "RegisterPerHourPerIp": 5,           // 严格配额只算「真的建出的账号」
    "ResendPerHourPerEmail": 5,
    "AuditLimit": 2000                   // 单账号保留的审计条数
  },

  "InboundAuth": {
    "Enabled": true,                     // 收信时做 SPF/DKIM/DMARC 校验
    "AddAuthenticationResults": true,    // 把结论写进报文的 Authentication-Results 头（标准做法）
    "SpamFolderOnFail": true,            // 判定为垃圾 → 投 spam 文件夹（可逆）
    "RejectOnDmarcReject": false,        // DMARC p=reject 且失败时直接 550 拒收（默认关：拒收不可逆）
    "VerifyDkim": true,                  // DKIM 验签（要查发件域 DNS 公钥；公钥发布成 CNAME 也会跟）
    "SpamScoreThreshold": 3,             // 判垃圾的分数阈值（DMARC 失败固定 +4）
    "DnsTimeoutSeconds": 5,
    "MaxSpfLookups": 10                  // RFC 7208 规定 10
  },

  "Smtp": {
    "MaxMessageBytes": 26214400,
    "AdvertiseStartTls": true,
    "AllowAuthOnInbound": false,         // 25 端口默认不允许认证
    "AddReceivedHeader": true,
    "AuthFailuresBeforeBan": 8,
    "BanMinutes": 15,
    "EnforceSenderMatch": true           // 已认证用户必须用自己的地址发件
  }
}
```

---

## 4. 构建与部署

```powershell
# 构建 + 自检（202 项；含 DKIM 可验证性、传输一致性、存储双后端契约、账号体系全套）
dotnet build -c Release
.\bin\Release\net8.0\win-x64\WpywMail.Native.exe --selftest

# 发布自包含版本（目标机无需安装 .NET）
dotnet publish -c Release -r win-x64 --self-contained true -o ..\work\publish-v2
```

增量部署（只换主程序集，不动配置与数据）：

```powershell
# ⚠ 顺序不能变：Stop-ScheduledTask 会触发任务的失败重启策略，把服务又拉起来并锁住 DLL
Disable-ScheduledTask -TaskName WpywMail
Stop-ScheduledTask    -TaskName WpywMail
Get-Process -Name 'WpywMail.Native' -ErrorAction SilentlyContinue | Stop-Process -Force
Copy-Item .\bin\Release\net8.0\win-x64\WpywMail.Native.dll 'C:\Program Files\WpywMail\WpywMail.Native.dll' -Force
Enable-ScheduledTask  -TaskName WpywMail
Start-ScheduledTask   -TaskName WpywMail
```

部署（计划任务名 `WpywMail`，动作指向 `C:\Program Files\WpywMail\WpywMail.Native.exe`）：

```powershell
Stop-ScheduledTask -TaskName WpywMail
Copy-Item ..\work\publish-v2\* 'C:\Program Files\WpywMail\' -Recurse -Force   # 运行时首次需全量，之后只需 *.dll/*.exe
Start-ScheduledTask -TaskName WpywMail
```

**回滚**：删掉 `C:\Program Files\WpywMail`，把 `C:\Program Files\WpywMail.v1-backup` 改回来，重启计划任务。

维护命令：

```powershell
WpywMail.Native.exe --version         # 版本
WpywMail.Native.exe --check-config    # 校验配置并打印关键项（含账号策略与「本机域免验证」提醒）
WpywMail.Native.exe --selftest        # 202 项自检（中文编解码、附件、DKIM、传输一致性、存储双后端契约、账号体系）
WpywMail.Native.exe --migrate         # 从 v1 数据迁移：重解析 raw/*.eml 修正主题/正文/附件、改写旧域名归属
```

### 4.1 真机验收脚本（账号体系）

`tools/account-acceptance.ps1` —— 在邮件服务器本机上跑，打**真实 HTTP API + 真实 IMAP(993)**：

```powershell
# 上传后在服务器上执行（脚本必须存成「UTF-8 带 BOM」，否则 PowerShell 5.1 会把中文按 GBK 解）
powershell -NoProfile -ExecutionPolicy Bypass -File account-acceptance.ps1
# 退出码 = 失败项数；报告默认写到 C:\Windows\Temp\wpyw-acct-verify.txt（UTF-8）
```

覆盖 53 项：策略接口 → 邀请码/域名/弱密码拦截 → 注册即开通 → 会话/资料/审计 →
真实 IMAP 登录与收件箱计数 → 自己发信并被本地投递 → 忘记密码（**真去邮箱里读验证码**）→ 重置 →
改密踢其他会话 → 登录失败锁定（423 + retryAfterSeconds）→ 管理员视角 → 停用与「不能靠重新注册复活」。

⚠ 脚本一小时内重复跑会撞到 `RegisterPerHourPerIp` 配额：此时它会把自助注册那几项标成 `[SKIP]`
并改用管理员接口建号，其余用例照常跑完（断言的是产品行为，不是配额余量）。
测试会留下两个 `selftest-*@` / `locktest-*@` 账号，脚本结束前会**停用**它们。

---

## 5. DNS 配置（决定能否进收件箱）

以 `wpy.email` + IP `<SERVER_IP>` 为例：

| 类型 | 名称 | 值 | 说明 |
|---|---|---|---|
| A | `mail` | `<SERVER_IP>` | **必须灰云（DNS only）**，MX 指向的主机不能走代理 |
| MX | `@` | `mail.example.com`（优先级 10） | |
| TXT | `@` | `v=spf1 ip4:<SERVER_IP> -all` | 注意是**半角**冒号；`-all` 比 `~all` 严格 |
| TXT | `mail._domainkey` | 服务启动日志里打印的 `v=DKIM1; k=rsa; p=...` | 一字不能改，Cloudflare 会自动分段 |
| TXT | `_dmarc` | `v=DMARC1; p=none; rua=mailto:wpy@wpy.email` | 先 `p=none` 观察，再收紧 |
| PTR | `56.55.236.103`（反向） | `mail.example.com` | **只能由 IDC 设置**，无 PTR 时大厂几乎必判垃圾 |

---

## 6. REST API

- 基址：`config.HttpPrefix`（默认 `http://127.0.0.1:8787/`，仅供反向代理/本机访问）
- 认证：`POST /api/login` 换 `token`，之后所有请求带 `Authorization: Bearer <token>`
- 编码：请求与响应均为 UTF-8 JSON；错误统一为 `{ "error": "说明" }`
- 会话有效期 `Api.SessionDays` 天，落盘保存，重启不掉线
- 所有路径保持 v1 兼容（`/api/login`、`/api/messages`、`/api/send`、`/api/config`、`/api/me`、`/api/logout`、`/api/account/password`、`/api/admin/users`）

### 6.1 无需认证

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/health` | `{ ok, service, version, domain, hostname }` |
| GET | `/api/version` | `{ version, domain, hostname, dkim }` |
| POST | `/api/login` | 入参 `{ email, password }` → `{ token, expiresAt, user }` |

### 6.2 账号

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/me` | `{ user, stats }`；stats 含 inbox/unread/starred/drafts/sent/trash/queue/failed |
| GET | `/api/config` | 域名、主机名、协议端口、特性开关（客户端据此决定是否显示附件/草稿入口） |
| POST | `/api/logout` | 使当前 token 失效 |
| POST | `/api/account/password` | `{ password, currentPassword? }`（新密码 ≥ 12 位）；成功后**吊销其他会话**，返回 `{ ok, revokedSessions }` |
| PATCH | `/api/account/profile` | `{ displayName }`（≤64 字）→ `{ ok, user }` |
| GET | `/api/account/sessions` | `{ sessions: [{ tokenPrefix, token, current, createdAt, expiresAt }] }` |
| POST | `/api/account/sessions/revoke` | 空体/`{}` = 退出其他设备（保留当前）；`{ all: true }` = 全部退出；`{ token }` = 指定会话 |
| GET | `/api/account/audit?limit=50` | `{ events: [{ at, email, ip, reason, success, detail, userAgent }] }`（自己的登录/改密/注册轨迹） |

### 6.2.1 自助注册与密码找回（v2.2 新增，无需认证）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/auth/policy` | 注册策略：`{ registration, inviteRequired, requireEmailVerification, minPasswordLength, allowedDomains, codeMinutes, maxLoginFailures, lockoutMinutes, selfHostedDomain, verificationNote }` |
| POST | `/api/register` | `{ email, password, displayName?, inviteCode? }` → `201 { ok, verificationRequired:false, session }`（直接开通）或 `202 { ok, verificationRequired:true, email, expiresInMinutes }`（等验证码） |
| POST | `/api/register/verify` | `{ email, code }` → `201 { ok, session }`（验证通过即登录） |
| POST | `/api/register/resend` | `{ email, purpose:"register"\|"reset" }` → `{ ok }` |
| POST | `/api/auth/forgot` | `{ email }` → 恒返回 `200 { ok, expiresInMinutes }`（**不暴露邮箱是否存在**；命中则发验证码邮件） |
| POST | `/api/auth/reset` | `{ email, code, password }` → `{ ok }`；成功后**吊销该账号全部会话**；若账号此前未激活（注册没验证完）顺带激活 |

登录失败的状态码（客户端要按码分支，别只看文案）：

| 码 | 何时 | 响应 |
|---|---|---|
| `401` | 账号不存在 / 密码错 / **账号被停用** | `{ error: "邮箱或密码不正确" }`（一句话，不区分原因，防账号枚举） |
| `403` | 账号存在但**注册的邮箱验证没做完** | `{ error: "...请用验证码完成验证，或用「忘记密码」重设密码", pendingVerification: true }` |
| `423` | 连续失败达到 `maxLoginFailures` 后的锁定期 | `{ error, retryAfterSeconds }`（客户端应显示倒计时并禁用提交） |

### 6.2.2 两条必须知道的设计决策（踩过坑才定下来的）

**① 本机托管的邮箱注册后免邮箱验证码。**
理由是个死循环：验证码邮件只能投进「这个」信箱，而这个信箱在验证通过前不允许登录（IMAP / Webmail / API 全进不去），
用户永远拿不到码。所以域名等于本服务器自己的域（`config.Domain` / `config.Hostname` 的域）时，
`RequireEmailVerification` 会被自动跳过，注册授权凭据是**邀请码**（管理员发放）。
`GET /api/auth/policy` 的 `verificationNote` 会把这件事讲给用户听；`--check-config` 也会打印同一提醒。
要让邮箱验证真正生效，得把 `Accounts.AllowedDomains` 换成托管在别处的域名（如 `gmail.com`）。
判定逻辑：`AccountService.IsHostedDomain(email, Domain, Hostname)`。

**② 未激活的账号先建信箱行，但密码只存在验证码记录里。**
注册时就把用户行建出来（`active=0`，密码是随机不可用值），否则本地投递看不到收件人、验证码邮件会被静默丢弃；
真正的密码哈希随验证码一起存进验证码记录的 Payload，**验证码通过那一刻才写进用户行并激活**。
于是「谁能读到验证码，谁才能决定这个账号的密码」—— 抢注者单独无法在别人的邮箱上留下自己的密码。
未激活的账号不能登录 IMAP/SMTP/API（各处 `FindUser` 只取 `active=1`），但**能收信**（投递用 `FindUserAnyState`）。

其它已实现的加固：注册/登录限流（严格配额只算**真的建出的账号**，填错表单不吃配额，另有宽松上限防邀请码爆破）、
验证码只存 PBKDF2 哈希 + 试错上限 + 过期、审计表（可按账号/IP/原因查询）、
**管理员停用是权威状态**（被停用的账号不能靠重新注册复活）、改密/重置后踢掉其他会话。

### 6.3 邮件

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/messages` | 查询：`folder`（inbox/sent/drafts/archive/trash/spam，留空=全部）、`q`、`unread=1`、`starred=1`、`limit`（≤500，默认 100）、`offset` → `{ total, offset, limit, messages[] }` |
| GET | `/api/messages/{id}` | 详情；查询 `markRead=false` 可只看不改已读状态 |
| PATCH | `/api/messages/{id}` | `{ unread?, read?, starred?, folder? }`（`folder` 即移动/归档/删除到垃圾箱） |
| DELETE | `/api/messages/{id}` | 默认移入垃圾箱；`?permanent=true` 彻底删除（同时删除原始报文与附件文件） |
| GET | `/api/messages/{id}/raw` | 下载原始 `.eml` |
| GET | `/api/messages/{id}/attachments/{index}` | 下载附件（`Content-Disposition` 为 RFC 5987 编码，中文名正常） |
| POST | `/api/send` | `{ to, subject, text, html?, cc?, inReplyTo?, attachments?[] }` → `202 { queued, messageId, recipients, cc }` |
| POST | `/api/drafts` | `{ to, subject, text }` → `201`，存入 drafts |

`messages[]` 摘要字段：`id, folder, from, to, cc, subject, date, receivedAt, unread, starred, deliveryStatus, lastError, size, attachmentCount, hasAttachments, preview`。

详情额外含：`text, html, messageId, inReplyTo, references, dkimSigned, attachments[{ index, fileName, contentType, size, inline, url }], rawUrl`。

`attachments` 元素格式：`{ fileName, contentType, base64 }`（单封上限见 `Smtp.MaxMessageBytes`）。

### 6.4 出站队列

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/queue` | `{ queue: [{ id, messageId, recipients, attempts, status, lastError, lastCode, nextAttempt, createdAt, lastAttemptAt }] }` |
| POST | `/api/queue/{id}/retry` | 立即重试（重置 attempts 与退避） |

`status`：`pending` / `processing` / `retry` / `sent` / `failed`。

### 6.5 新邮件推送（长轮询）

```
GET /api/watch?since=<version>
→ 挂起至多 Api.LongPollSeconds 秒，直到数据发生变化
→ { version, changed, stats }
```

客户端流程：启动时 `version = (await /api/watch?since=0).version`，之后循环
`/api/watch?since=<上次的 version>`；`changed=true` 时刷新列表，并把返回的 `version` 作为下次的 `since`。

### 6.6 管理员

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/admin/users` | 用户列表（含 active / createdAt / lastLoginAt） |
| POST | `/api/admin/users` | `{ email, password(≥12), displayName? }` → `201` |
| PATCH | `/api/admin/users/{email}` | `{ active? }` 或 `{ password? }` |

---

## 7. 客户端接入要点

**登录**

```http
POST /api/login  {"email":"wpy@wpy.email","password":"..."}
→ 200 {"token":"...","expiresAt":"...","user":{"email":"...","displayName":"...","role":"admin","domain":"wpy.email"}}
```
之后每个请求加 `Authorization: Bearer <token>`；收到 `401` 即视为需要重新登录（本地清 token）。

**SMTP 客户端（手机/电脑上的邮件 App）**：`587` + STARTTLS + 普通密码认证（`AUTH LOGIN/PLAIN`），发件人必须等于登录账号；`25` 端口只用于收信，不接受认证与中继。

**WinUI 客户端建议**：走 REST + `/api/watch` 长轮询即可，无需实现 IMAP/SMTP；
若要支持系统级邮件 App，则需另加 IMAP（v2 尚未实现，见第 8 节）。

**错误处理**：`400` 参数问题、`401` 未登录、`403` 权限/密码错误、`404` 对象不存在、`405` 方法不支持、`500` 服务端异常；响应体固定为 `{ error }`。

**并发**：长轮询会占用一个连接，建议单个客户端同时最多 1 个 watch 请求。

---

## 8. 用标准邮件客户端接入（IMAP）

v2 内置 IMAP4rev1 服务端，Thunderbird / Outlook / Foxmail / 手机邮件 App 可直接连接。

| 项目 | 值 |
|---|---|
| 明文 + STARTTLS | 端口 `143` |
| 隐式 TLS | 端口 `993` |
| 用户名 | 完整邮箱地址，如 `wpy@wpy.email` |
| 密码 | `appsettings.json` 里的 `AdminPassword` |
| 发信（SMTP） | `587` + STARTTLS + 同一套账号密码 |
| 收信（SMTP） | 无需配置（`25` 由公网直接投递） |

文件夹映射（客户端里显示名 → 内部名）：
`INBOX`→inbox、`Sent`→sent、`Drafts`→drafts、`Archive`→archive、`Trash`→trash、`Junk`→spam。
中文名（收件箱/已发送/草稿/归档/垃圾箱/垃圾邮件）也可被识别。

已实现的命令：`CAPABILITY`、`NOOP`、`LOGOUT`、`STARTTLS`、`LOGIN`、`AUTHENTICATE PLAIN`、
`LIST`/`LSUB`、`SELECT`/`EXAMINE`、`STATUS`、`CLOSE`、`UNSELECT`、`EXPUNGE`、`SEARCH`、
`FETCH`/`UID FETCH`、`STORE`/`UID STORE`、`COPY`/`UID COPY`、`APPEND`、`IDLE`、
`CREATE`/`DELETE`/`RENAME`/`SUBSCRIBE`（接受但文件夹集合固定）。
未实现（不影响常规使用）：`SORT`、`THREAD`、`CONDSTORE`、`QRESYNC`、`ACL`。

行为约定：

- `RequireTlsForLogin=true` 时，**必须先 STARTTLS 或用 993** 才能 LOGIN；仅 `PlaintextLoginAllowFrom` 列表内的地址（默认本机）可明文登录。
- `SELECT` 后 `FETCH` 的序号按 **UID 升序**（稳定顺序）。
- 非 `PEEK` 的正文请求会把邮件标记为已读；`\Flagged` ↔ 星标；`\Deleted` 在 `EXPUNGE` 时生效（inbox 等移入垃圾箱，垃圾箱内则彻底删除）。
- `EXPUNGE` 的序号会随删除动态变化（符合 RFC 3501）。
- 自签名证书下客户端会提示证书不受信；换成受信任证书后即无提示。

配置示例（appsettings.json）：

```jsonc
"Imap": {
  "Enabled": true,
  "Port": 143,
  "TlsPort": 993,
  "RequireTlsForLogin": true,
  "PlaintextLoginAllowFrom": ["127.0.0.1", "::1"]
}
```

---

## 9. 存储后端（SQLite / JSON）

### 为什么要有这一节

v2.0.x 只有一种存储：`users.json / messages.json / queue.json / sessions.json` 四个文件，
**任何一次改动都会把全部邮件重新序列化并整文件重写**。把一封邮件标记为已读也是 O(N)，
UID 分配、未读计数、统计、搜索全是全表扫描，而且全部邮件常驻内存。

v2.1 起默认使用 **SQLite**（元数据进库 + 索引 + 事务），原始报文与附件以
**gzip 压缩 + 按内容 SHA256 去重**的形式存进 `blobs` 表 —— **不再写 `raw/` 文件**。

### 基准数据（同一份负载，`--bench-store`）

| 指标 | JSON（整文件重写） | SQLite | 结论 |
|---|---|---|---|
| 入库 每封 @400 封 | 3.74 ms | 0.27 ms | **快 14×** |
| 入库 每封 @2000 封 | 9.94 ms | 0.36 ms | **快 28×**（JSON 随规模劣化） |
| 标记已读 每次 @2000 | 16.50 ms | 0.10 ms | **快 167×** |
| 收件箱首页（50 条） | 0.42 ms | 0.97 ms | 都在毫秒级 |
| 未读数 | 0.13 ms | 0.06 ms | 快 2× |
| 统计 | 0.17 ms | 0.18 ms | 持平 |
| 搜索（LIKE 扫描） | 6.27 ms | 7.30 ms | 持平；**开 FTS5 后 0.35 ms（快 18×）** |
| 常驻内存增量 @2000 | 24.5 MB | 7.5 MB | **省 69%** |
| 磁盘 @2000 | 10.56 MB | 7.03 MB | **省 33%**（raw 808 KB→库内 273 KB） |

关键不是单点快多少，而是**增长曲线**：JSON 的单次改动成本随邮件数线性上涨（400→2000 封时
每封入库从 3.7 ms 涨到 9.9 ms），SQLite 基本恒定。

### 命令

```powershell
WpywMail.Native.exe --storage-status      # 当前后端、各表占用、大对象压缩率、有无孤儿
WpywMail.Native.exe --migrate-to-sqlite    # JSON → SQLite（逐封 SHA256 校验，默认保留源文件）
WpywMail.Native.exe --migrate-to-sqlite --delete-source   # 校验通过后删除 raw/ 与 attachments/ 文件
WpywMail.Native.exe --migrate-to-json      # SQLite → JSON（回滚用，把 blobs 还原成文件）
WpywMail.Native.exe --compact              # 清理没有引用的大对象
WpywMail.Native.exe --vacuum               # 合并 WAL + 回收空闲页
WpywMail.Native.exe --bench-store 2000     # 两套后端的基准对比
```

### 迁移与回滚

1. 停服务（**先 `Disable-ScheduledTask WpywMail`**，否则任务的失败重启策略会把它拉起来、锁住 DLL）；
2. 备份 `C:\WpywMailData`；
3. `--migrate-to-sqlite --delete-source`：迁移会**逐封比对 SHA256**，任何一封不一致就中止并保留源文件；
4. 改 `Storage.Provider` 为 `sqlite`（默认值即是），启服务。

**回滚**：把 `Storage.Provider` 改回 `json` 即可 —— 四个 JSON 索引文件在迁移时**故意保留**。
若源文件已被 `--delete-source` 删除导致 JSON 侧缺 `raw/`，先跑 `--migrate-to-json`
把 blobs 还原成文件，再切回 json。

### ⚠️ `--vacuum` 必须在停服时做

VACUUM 需要约 **2 倍**临时空间，且 **WAL 无法在别的连接持有数据库时截断** ——
在服务运行时执行会把文件撑大而收不回来（实测 241 KB → 1.75 MB，停服重做后回到 274 KB）。

### 空间账（本机实测，66 封邮件）

```
raw/            0 B（0 个文件）      ← 报文字节已压缩进库
attachments/    0 B（0 个文件）
wpywmail.db     274,432 B（67 页 × 4096 B，空闲页 0）
  大对象 59 个：原始 88,917 B → 存储 49,986 B（57 个启用压缩）
  正文列合计 47,853 B（最大一封 8,908 B：port25 的 Authentication Report）
```

平均约 4.2 KB/封（含索引）。索引不是免费的：`ux_messages_owner_folder_uid`、
`ix_messages_owner_folder_date`、`ix_messages_owner_unread`、`ix_messages_owner_starred`、
`ix_messages_owner_status` 都对应真实查询；早期版本建过两个没人用的索引（`message_id`、`raw_path`），
已在建表语句里幂等 `DROP` 掉。

---

## 10. 全文检索开关（FTS5）

`Storage.FullTextSearch: true` 会建立 FTS5（trigram 分词器）索引，中文子串搜索走索引：

| | 搜索每次 @2000 封 | 占用 |
|---|---|---|
| `false`（默认） | 7.30 ms（`LIKE '%…%'` 全表扫描） | 7,028,736 B |
| `true` | **0.35 ms** | 9,777,152 B（**索引多占 2.7 MB ≈ 1.4 KB/封**） |

默认关闭是因为本机磁盘偏紧；按 12.5 GB 可用空间算，索引成本要到**上百万封**才会成为问题，
所以只要搜索体验优先，随时可以打开（改配置重启即可，首次启动会自动为历史邮件建索引）。

---

### 10.1 入站邮件身份校验（SPF / DKIM / DMARC）

在此之前**谁都能用 `From: wpy@wpy.email` 给这台服务器发信**，服务器照单全收进收件箱 —— 冒名邮件和正常邮件没有区别。
现在收信时依次做：

| 步骤 | 实现 | 说明 |
|---|---|---|
| SPF | `Spf.EvaluateAsync`（RFC 7208 常用子集） | all / include / a / mx / ip4 / ip6 / exists + 限定符 + redirect + 宏；**查询次数上限 10**（超了 permerror）；`ptr` 机制按 RFC 建议直接视为不匹配 |
| DKIM | `DkimVerifier`（RFC 6376） | relaxed/simple 规范化、`h=` 重名从下往上取、`l=` 截断、`x=` 过期、`p=` 为空视为吊销；**公钥发布成 CNAME 时会自动跟**（outlook.com 就是这种） |
| DMARC | `Dmarc.EvaluateAsync`（RFC 7489） | `p=` / `aspf=` / `adkim=`；relaxed 对齐用「组织域」（内置 co.uk / com.cn 这类多段后缀表） |

结论会写进报文：`Authentication-Results:`、`X-Spam-Score:`、`X-Spam-Reason:`（**前置插入，不动原有字节**，
所以发件人的 DKIM 签名不会被我们破坏 —— 自检里有这条断言）。
判定为垃圾（默认阈值 3；DMARC 失败固定 +4）则投进 `spam` 文件夹并把 `DeliveryStatus` 标成 `received-spam`，
**默认不拒收**：校验实现自身也可能有 bug，投垃圾箱可逆、拒收不可逆。

**验签实现必须能被打假**：自检里带了「改正文 / 改主题 / 只翻转一个字节 / 换公钥 / 公钥吊销」五类反向用例，
它们必须全部失败 —— 2026-09-13 的 DKIM 事故就是签名端和验签端犯了同一个错，导致自检「全通过」而外部判 fail。

维护命令：**`--verify-inbound [N]`** —— 对已落库的真实邮件走真实 DNS 验签（排查「这封信是不是伪造的」）。
实测最近 25 封里 8 封通过（含 126.com 这类第三方签名），1 封 163 转发的因正文被改写而判 fail（**判定正确**）。

---

## 11. 已知限制
- ~~未实现 IMAP/POP3~~ → **IMAP4rev1 已在 v2 实现**（见第 8 节）；POP3 仍未实现。
- ~~TLS 证书自签名~~ → **已换成 Let's Encrypt 受信任证书**（DNS-01，含自动续期计划任务）。
- ~~无账号体系~~ → **v2.2 已有自助注册 / 登录加固 / 找回密码 / 会话与资料管理**（见第 6.2 节）；
  仍缺：**管理员删除账号**（目前只能停用，`PATCH /api/admin/users/{email}` `{"active":false}`）。
- **明文凭据**：`appsettings.json` 中的 `AdminPassword` 与证书口令是明文，注意文件权限。
- **无病毒/垃圾过滤**：收信不做内容扫描，也未做 SPF/DKIM 校验入站判定。
- **默认无全文索引**：搜索是 `LIKE` 扫描（数千封内毫秒级）；需要更快请开 `FullTextSearch`。
- **无配额**：单用户磁盘占用不限制。
- **`--vacuum` 需停服执行**（见第 9 节）。
