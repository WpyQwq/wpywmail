using System.Text.Json.Serialization;

namespace WpywMail.Native;

/// <summary>应用配置。对应 appsettings.json 的根对象。</summary>
public sealed class AppConfig
{
    public string Domain { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string HttpPrefix { get; set; } = "http://127.0.0.1:8787/";
    public int SmtpPort { get; set; } = 25;
    public int SubmissionPort { get; set; } = 587;
    public string DataDirectory { get; set; } = "";
    public string AdminEmail { get; set; } = "";
    public string AdminPassword { get; set; } = "";
    public string TlsCertificatePath { get; set; } = "";
    public string TlsCertificatePassword { get; set; } = "";

    /// <summary>direct = 按 MX 直接投递；relay = 走上游 SMTP 中继。</summary>
    public string DeliveryMode { get; set; } = "direct";

    public DirectDeliveryConfig DirectDelivery { get; set; } = new();
    public RelayConfig Relay { get; set; } = new();
    public RetryConfig Retry { get; set; } = new();
    public DkimConfig Dkim { get; set; } = new();
    public ApiConfig Api { get; set; } = new();
    public ImapConfig Imap { get; set; } = new();
    public SmtpConfig Smtp { get; set; } = new();
    public StorageConfig Storage { get; set; } = new();
    public AccountsConfig Accounts { get; set; } = new();
    public InboundAuthConfig InboundAuth { get; set; } = new();

    /// <summary>启动时做基本校验，尽早暴露配置错误。</summary>
    public void Validate()
    {
        if (string.IsNullOrWhiteSpace(Domain)) throw new InvalidOperationException("appsettings.json 必须设置 Domain。");
        if (string.IsNullOrWhiteSpace(Hostname)) throw new InvalidOperationException("appsettings.json 必须设置 Hostname。");
        if (string.IsNullOrWhiteSpace(AdminEmail) || !AdminEmail.Contains('@')) throw new InvalidOperationException("AdminEmail 必须是完整的邮箱地址。");
        if (!AdminEmail.EndsWith("@" + Domain, StringComparison.OrdinalIgnoreCase))
            AppLog.Warn($"[配置] AdminEmail（{AdminEmail}）不在 Domain（{Domain}）之下，请确认这是有意的。");
        if (AdminPassword.Length < 12) throw new InvalidOperationException("请在 appsettings.json 设置至少 12 位 AdminPassword。");
        if (AdminPassword.Contains("replace-with", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("AdminPassword 还是示例值，请改成真实密码。");
        if (string.IsNullOrWhiteSpace(DataDirectory)) throw new InvalidOperationException("appsettings.json 必须设置 DataDirectory。");
        if (!DeliveryMode.Equals("direct", StringComparison.OrdinalIgnoreCase) && !DeliveryMode.Equals("relay", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("DeliveryMode 只能是 direct 或 relay。");
        if (DeliveryMode.Equals("relay", StringComparison.OrdinalIgnoreCase) && string.IsNullOrWhiteSpace(Relay.Host))
            throw new InvalidOperationException("DeliveryMode=relay 时必须设置 Relay.Host。");
        if (SmtpPort is < 1 or > 65535 || SubmissionPort is < 1 or > 65535) throw new InvalidOperationException("SMTP 端口配置非法。");
        if (SmtpPort == SubmissionPort) throw new InvalidOperationException("SmtpPort 与 SubmissionPort 不能相同。");
        if (!Storage.Provider.Equals("json", StringComparison.OrdinalIgnoreCase) &&
            !Storage.Provider.Equals("sqlite", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Storage.Provider 只能是 json 或 sqlite。");

        var registration = (Accounts.Registration ?? "").Trim().ToLowerInvariant();
        if (registration is not ("open" or "invite" or "closed"))
            throw new InvalidOperationException("Accounts.Registration 只能是 open / invite / closed。");
        if (registration == "invite" && string.IsNullOrWhiteSpace(Accounts.InviteCode))
            throw new InvalidOperationException("Accounts.Registration=invite 时必须设置 Accounts.InviteCode。");
        if (Accounts.MinPasswordLength < 8)
            throw new InvalidOperationException("Accounts.MinPasswordLength 不能小于 8。");
        if (Accounts.CodeMinutes < 1 || Accounts.CodeMinutes > 24 * 60)
            throw new InvalidOperationException("Accounts.CodeMinutes 应在 1..1440 之间。");
    }
}

/// <summary>
/// 账号体系配置：自助注册策略、邮箱验证、密码强度、登录锁定、限流。
///
/// 默认值刻意偏保守：**注册默认 invite（需要邀请码）**，且注册的邮箱域名默认只允许
/// 服务器自己的 Domain —— 公网上的邮件服务器一旦开放注册，很快就会变成垃圾邮件跳板。
/// 要真正开放，请显式改 Registration=open 并配置 AllowedDomains。
/// </summary>
public sealed class AccountsConfig
{
    /// <summary>open = 任何人可注册；invite = 需要邀请码；closed = 关闭注册（只能管理员建号）。</summary>
    public string Registration { get; set; } = "invite";

    /// <summary>invite 模式下的邀请码。</summary>
    public string InviteCode { get; set; } = "";

    /// <summary>允许注册的邮箱域名（含服务器自身域名）。留空表示只允许 Domain。</summary>
    public string[] AllowedDomains { get; set; } = [];

    /// <summary>注册后是否必须用邮箱里的验证码激活（强烈建议 true）。</summary>
    public bool RequireEmailVerification { get; set; } = true;

    /// <summary>密码最小长度（同时会检查：不能是纯数字、不能与邮箱相同）。</summary>
    public int MinPasswordLength { get; set; } = 12;

    /// <summary>验证码有效期（分钟）。</summary>
    public int CodeMinutes { get; set; } = 30;

    /// <summary>同一个验证码最多尝试几次（超过即作废，需重新获取）。</summary>
    public int MaxCodeAttempts { get; set; } = 5;

    /// <summary>同一账号在窗口期内连续登录失败多少次后锁定。</summary>
    public int MaxLoginFailures { get; set; } = 8;

    /// <summary>登录失败统计窗口与锁定时长（分钟）。</summary>
    public int LockoutMinutes { get; set; } = 15;

    /// <summary>同一 IP 每小时最多发起几次注册 / 重发验证码（防刷）。</summary>
    public int RegisterPerHourPerIp { get; set; } = 5;

    /// <summary>同一邮箱每小时最多重发几次验证码。</summary>
    public int ResendPerHourPerEmail { get; set; } = 5;

    /// <summary>审计日志最多保留多少条（超出后按时间淘汰）。</summary>
    public int AuditLimit { get; set; } = 2000;

    /// <summary>把配置里的域名规则解析成实际允许的域名集合。</summary>
    public string[] EffectiveDomains(string serverDomain)
    {
        var list = AllowedDomains
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .Select(x => x.Trim().TrimStart('@').ToLowerInvariant())
            .ToList();
        if (list.Count == 0 && !string.IsNullOrWhiteSpace(serverDomain))
            list.Add(serverDomain.Trim().TrimStart('@').ToLowerInvariant());
        return [.. list.Distinct()];
    }
}

/// <summary>
/// 存储后端选择。
///
/// - json   ：v2.0.x 的原始实现，users/messages/queue/sessions 各一个 JSON 文件，
///            **任何一次改动都会整文件重写**，随邮件量增长呈 O(N) 放大。
/// - sqlite ：SQLite 单文件数据库（元数据 + 索引 + 事务），原始报文仍落在 raw/ 目录。
///            默认值，也是推荐值；改回 json 即可一键回滚（两套数据互不覆盖）。
/// </summary>
public sealed class StorageConfig
{
    public string Provider { get; set; } = "sqlite";

    /// <summary>SQLite 数据库文件路径；留空则用 DataDirectory/wpywmail.db。</summary>
    public string DatabasePath { get; set; } = "";

    /// <summary>WAL 模式下定期检查点阈值（页数），0 表示交给 SQLite 默认策略。</summary>
    public int WalAutoCheckpointPages { get; set; }

    /// <summary>
    /// 是否为正文建立 FTS5（trigram）全文索引。
    /// 打开后搜索从「全表 LIKE 扫描」变成索引命中，代价是**索引本身会额外占用接近正文大小的磁盘**
    /// （trigram 索引通常与正文同量级）。默认关闭，因为本机磁盘偏紧、而 LIKE 在数千封量级仍是毫秒级。
    /// </summary>
    public bool FullTextSearch { get; set; }
}

public sealed class DirectDeliveryConfig
{
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    public int CommandTimeoutSeconds { get; set; } = 30;
    public int DnsTimeoutSeconds { get; set; } = 5;
    public bool OpportunisticStartTls { get; set; } = true;
    public bool RequireStartTls { get; set; }
    public string DnsServer { get; set; } = "";
    /// <summary>投递时使用的 HELO 名称，留空则用 Hostname。</summary>
    public string HeloName { get; set; } = "";
}

public sealed class RelayConfig
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public bool EnableSsl { get; set; } = true;
}

/// <summary>失败重投策略。4xx（临时）与 5xx（永久）分开处理。</summary>
public sealed class RetryConfig
{
    public int MaxAttempts { get; set; } = 12;
    public int InitialDelaySeconds { get; set; } = 60;
    public int MaxDelaySeconds { get; set; } = 3600;
    /// <summary>5xx 默认也重试若干次：封锁/策略类 5xx 往往是临时的。</summary>
    public bool RetryOnPermanentFailure { get; set; } = true;
    public int MaxAttemptsForPermanent { get; set; } = 3;
    /// <summary>彻底失败时给发件人投递退信（NDR）。</summary>
    public bool SendBounceNotification { get; set; } = true;
}

/// <summary>DKIM 签名配置。私钥不存在时会自动生成并打印需要配置的 DNS 记录。</summary>
public sealed class DkimConfig
{
    public bool Enabled { get; set; }
    public string Selector { get; set; } = "mail";
    /// <summary>留空则用 Domain。</summary>
    public string SigningDomain { get; set; } = "";
    /// <summary>留空则放在 DataDirectory/dkim/&lt;selector&gt;.private.pem。</summary>
    public string PrivateKeyPath { get; set; } = "";
    public string[] Headers { get; set; } =
        ["From", "To", "Subject", "Date", "Message-ID", "MIME-Version", "Content-Type", "Content-Transfer-Encoding"];
}

/// <summary>
/// 入站邮件身份校验（SPF / DKIM / DMARC）与垃圾邮件判定。
///
/// 默认策略：**标注 + 投垃圾箱，不拒收** —— 校验实现自身也可能有 bug，拒收不可逆，
/// 投进垃圾箱可逆。要严格拒收把 <see cref="RejectOnDmarcReject"/> 打开。
/// </summary>
public sealed class InboundAuthConfig
{
    public bool Enabled { get; set; } = true;
    /// <summary>是否往报文里写 Authentication-Results / X-Spam-Score 头（标准做法，保留证据）。</summary>
    public bool AddAuthenticationResults { get; set; } = true;
    /// <summary>判定为垃圾时投进 spam 文件夹而不是收件箱。</summary>
    public bool SpamFolderOnFail { get; set; } = true;
    /// <summary>DMARC p=reject 且校验失败时直接在 SMTP 阶段 550 拒收。默认关（怕误杀）。</summary>
    public bool RejectOnDmarcReject { get; set; } = false;
    /// <summary>DKIM 验签（含 DNS 取公钥）开关；关掉只做 SPF/DMARC 的 SPF 部分。</summary>
    public bool VerifyDkim { get; set; } = true;
    /// <summary>判为垃圾的分数阈值（DMARC 失败固定 +4）。</summary>
    public int SpamScoreThreshold { get; set; } = 3;
    public int DnsTimeoutSeconds { get; set; } = 5;
    /// <summary>SPF 的 DNS 查询次数上限（RFC 7208 规定 10）。</summary>
    public int MaxSpfLookups { get; set; } = 10;
}

public sealed class ApiConfig
{
    public int SessionDays { get; set; } = 30;
    /// <summary>允许的跨域来源；默认 * 便于本机客户端调试，公网使用建议收紧。</summary>
    public string CorsOrigin { get; set; } = "*";
    /// <summary>推送新邮件的长轮询上限（秒）。</summary>
    public int LongPollSeconds { get; set; } = 25;
    /// <summary>
    /// 可选的公网 HTTPS 前缀（例如 <c>https://mail.example.com:9443/</c>），只为客户端在公网
    /// 自助注册 / 找回密码 / 管理会话资料而开。**只放行账号类接口**，邮件读写与管理接口不在这里暴露。
    /// 留空 = 不开（默认）。HTTPS 前缀必须先绑定证书：<c>netsh http add sslcert hostnameport=mail.example.com:9443 ...</c>
    /// </summary>
    public string PublicPrefix { get; set; } = "";
}

/// <summary>IMAP 服务配置（让标准邮件客户端也能接入）。</summary>
public sealed class ImapConfig
{
    public bool Enabled { get; set; } = true;
    /// <summary>143：明文 + STARTTLS。</summary>
    public int Port { get; set; } = 143;
    /// <summary>993：隐式 TLS。设为 0 表示不监听。</summary>
    public int TlsPort { get; set; } = 993;
    /// <summary>是否要求先建立 TLS 才允许 LOGIN（推荐 true）。</summary>
    public bool RequireTlsForLogin { get; set; } = true;
    /// <summary>允许未加密登录的来源地址（默认仅本机，便于自检/调试）。</summary>
    public string[] PlaintextLoginAllowFrom { get; set; } = ["127.0.0.1", "::1"];
}

public sealed class SmtpConfig
{
    /// <summary>单封邮件最大字节数。</summary>
    public int MaxMessageBytes { get; set; } = 25 * 1024 * 1024;
    /// <summary>是否始终广告 STARTTLS（只要加载到证书就广告，含自签名）。</summary>
    public bool AdvertiseStartTls { get; set; } = true;
    /// <summary>25 端口也允许 AUTH（默认否；587 端口始终允许）。</summary>
    public bool AllowAuthOnInbound { get; set; }
    /// <summary>给收到的邮件补 Received 头。</summary>
    public bool AddReceivedHeader { get; set; } = true;
    /// <summary>同一 IP 连续认证失败多少次后临时封禁。</summary>
    public int AuthFailuresBeforeBan { get; set; } = 8;
    public int BanMinutes { get; set; } = 15;
    /// <summary>已认证用户是否必须使用自己的地址作为发件人。</summary>
    public bool EnforceSenderMatch { get; set; } = true;
}

public sealed class MailUser
{
    public string Email { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    public bool Active { get; set; } = true;
    public string Role { get; set; } = "user";
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastLoginAt { get; set; }
}

public sealed class Attachment
{
    public string FileName { get; set; } = "";
    public string ContentType { get; set; } = "application/octet-stream";
    public long Size { get; set; }
    /// <summary>相对 DataDirectory 的存储路径，例如 attachments/xxx.bin。</summary>
    public string StoredAs { get; set; } = "";
    public string ContentId { get; set; } = "";
    public bool Inline { get; set; }
}

public sealed class MailMessage
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OwnerEmail { get; set; } = "";
    /// <summary>inbox / sent / drafts / archive / trash / spam</summary>
    public string Folder { get; set; } = "inbox";
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    public string Cc { get; set; } = "";
    public string Subject { get; set; } = "(无主题)";
    public string Text { get; set; } = "";
    public string Html { get; set; } = "";
    public string RawPath { get; set; } = "";
    public string MessageId { get; set; } = "";
    public string InReplyTo { get; set; } = "";
    public string References { get; set; } = "";
    public DateTimeOffset Date { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset ReceivedAt { get; set; } = DateTimeOffset.UtcNow;
    public bool Unread { get; set; } = true;
    public bool Starred { get; set; }
    /// <summary>IMAP UID：在同一文件夹内单调递增且稳定，首次入库时分配。</summary>
    public int Uid { get; set; }
    /// <summary>received / queued / sent / failed</summary>
    public string DeliveryStatus { get; set; } = "received";
    public string LastError { get; set; } = "";
    public long Size { get; set; }
    public List<Attachment> Attachments { get; set; } = [];
    public bool HasAttachments => Attachments.Count > 0;
    /// <summary>DKIM 是否签名成功（发件侧）。</summary>
    public bool DkimSigned { get; set; }
}

public sealed class QueueItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string MessageId { get; set; } = "";
    public string OwnerEmail { get; set; } = "";
    public string[] Recipients { get; set; } = [];
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset NextAttempt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? LastAttemptAt { get; set; }
    /// <summary>pending / processing / retry / sent / failed</summary>
    public string Status { get; set; } = "pending";
    public string LastError { get; set; } = "";
    public int LastCode { get; set; }
}

public sealed class SessionRecord
{
    public string Token { get; set; } = "";
    public string Email { get; set; } = "";
    public DateTimeOffset Expires { get; set; } = DateTimeOffset.UtcNow.AddDays(30);
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed record LoginRequest(string Email, string Password);

// ─────────────────────────────────────────────────────────── 账号体系

/// <summary>
/// 邮箱验证码（注册激活 / 密码重置共用一个表）。
///
/// 只存**验证码的哈希**，不存明文 —— 数据库被人拿到也不能直接拿来激活账号或改密码。
/// 注册场景下，密码的哈希与显示名先暂存在 Payload 里，验证通过后才真正建号，
/// 这样「未验证的注册」不会在用户表里留下垃圾数据。
/// </summary>
public sealed class VerificationCode
{
    public string Email { get; set; } = "";
    /// <summary>register = 注册激活；reset = 重置密码。</summary>
    public string Purpose { get; set; } = "register";
    public string CodeHash { get; set; } = "";
    public string Salt { get; set; } = "";
    /// <summary>register 时是 JSON：{ displayName, passwordHash, passwordSalt }。</summary>
    public string Payload { get; set; } = "";
    public DateTimeOffset ExpiresAt { get; set; } = DateTimeOffset.UtcNow.AddMinutes(30);
    public int Attempts { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? SentAt { get; set; }
}

/// <summary>
/// 认证事件审计：登录成功/失败、注册、验证码发送与校验、密码重置、会话吊销。
/// 用途有三个：排查问题、登录锁定判定、按 IP/邮箱做限流。
/// </summary>
public sealed class AuthEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Email { get; set; } = "";
    public string Ip { get; set; } = "";
    /// <summary>login-ok / login-failed / login-locked / register / register-verify / code-sent / reset-ok / session-revoked</summary>
    public string Reason { get; set; } = "";
    public bool Success { get; set; }
    public string Detail { get; set; } = "";
    public string UserAgent { get; set; } = "";
    public DateTimeOffset At { get; set; } = DateTimeOffset.UtcNow;
}

public sealed record RegisterRequest(string Email, string Password, string? DisplayName = null, string? InviteCode = null);

public sealed record VerifyCodeRequest(string Email, string Code);

public sealed record ResetPasswordRequest(string Email, string Code, string Password);

public sealed record ProfileRequest(string? DisplayName = null);

/// <summary>附件上传：内容用 base64 传递。</summary>
public sealed record AttachmentRequest(string FileName, string ContentType, string Base64);

public sealed record SendRequest(
    string To,
    string Subject,
    string? Text,
    string? Html = null,
    string? Cc = null,
    string? InReplyTo = null,
    List<AttachmentRequest>? Attachments = null);

public sealed record DraftRequest(string To, string Subject, string Text);
