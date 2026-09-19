using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WpywMail.Native;

/// <summary>
/// 账号体系的业务层：自助注册、邮箱验证码、失败锁定、密码重置、会话与资料管理。
///
/// 设计取舍（都在代码里写清楚，方便以后回看）：
///
/// 1. **先建未激活信箱，密码等验证通过才写入**：本地投递只认已存在的用户，所以注册时必须
///    先把信箱行建出来（否则验证码邮件会被判成外发、甚至直接丢弃，用户永远收不到码）；
///    但这一行的密码是**随机不可用值**，真正的密码存在验证码记录的 Payload 里，
///    验证通过后才写进用户行并激活 —— 于是「谁能读到验证码，谁才能决定这个账号的密码」。
///    未激活的信箱不能登录 IMAP/SMTP/API（见各处的 FindUser 只取 active=1）。
///    ⚠️ 曾经写成「验证通过再建号」，结果是验证码邮件根本送不到，属于致命流程缺陷。
/// 2. **验证码只存哈希**：库被拖走也不能直接拿来激活账号或改密码。
/// 3. **登录失败信息不区分原因**：对外一律「邮箱或密码不正确」，避免账号枚举；
///    真实原因（不存在 / 密码错 / 已停用 / 已锁定）只写进审计日志。
/// 4. **发信走既有出站队列**：验证码邮件复用 Mime.Build + QueueOutbound + 投递队列，
///    不另起一条发送路径（否则重试、DKIM、队列状态都要再实现一遍）。
/// </summary>
public sealed class AccountService
{
    private readonly AppConfig config;
    private readonly IMailStore store;

    public AccountService(AppConfig config, IMailStore store)
    {
        this.config = config;
        this.store = store;
        // 让存储层的审计裁剪跟随配置
        if (store is SqliteStore sqlite) sqlite.AuditKeep = config.Accounts.AuditLimit;
        if (store is FileStore file) file.AuditKeep = config.Accounts.AuditLimit;
        if (config.Accounts.RequireEmailVerification
            && config.Accounts.EffectiveDomains(config.Domain)
                .All(d => IsHostedDomain("x@" + d, config.Domain, config.Hostname)))
        {
            AppLog.Warn("[账号] Accounts.RequireEmailVerification=true，但允许注册的域名都由本机托管 —— "
                + "验证码邮件会被投进「验证通过前登录不了」的信箱，形成死循环。"
                + "对这些地址已自动跳过邮箱验证（注册授权凭据是邀请码）。"
                + "要让邮箱验证真正生效，请把 AllowedDomains 换成托管在别处的域名（如 gmail.com）。");
        }
    }

    public AccountsConfig Policy => config.Accounts;

    // ---------------------------------------------------------------- 对外：策略

    public object PolicyView() => new
    {
        registration = Policy.Registration,
        inviteRequired = Policy.Registration.Equals("invite", StringComparison.OrdinalIgnoreCase),
        requireEmailVerification = Policy.RequireEmailVerification,
        minPasswordLength = Policy.MinPasswordLength,
        allowedDomains = Policy.EffectiveDomains(config.Domain),
        codeMinutes = Policy.CodeMinutes,
        maxLoginFailures = Policy.MaxLoginFailures,
        lockoutMinutes = Policy.LockoutMinutes,
        selfHostedDomain = config.Domain,
        verificationNote = Policy.RequireEmailVerification
            ? $"本机托管的邮箱（@{config.Domain}）注册后免验证码直接开通：验证码邮件只能投进这个信箱，"
              + "而它在验证通过前登录不了，会形成死循环；这类地址的授权凭据是邀请码。"
            : "",
    };

    /// <summary>该地址的信箱是否就托管在本机上（域名 = 本服务器自己的域）。</summary>
    public bool IsHostedHere(string? email) => IsHostedDomain(email, config.Domain, config.Hostname);

    /// <summary>纯函数版本：不依赖存储，供 --check-config 等只读场景使用。</summary>
    public static bool IsHostedDomain(string? email, string? domain, string? hostname)
    {
        var at = (email ?? "").LastIndexOf('@');
        if (at < 0 || at == email!.Length - 1) return false;
        var d = email[(at + 1)..].Trim().ToLowerInvariant();
        if (d.Length == 0) return false;
        if (d.Equals((domain ?? "").Trim().ToLowerInvariant(), StringComparison.Ordinal)) return true;
        var host = (hostname ?? "").Trim().ToLowerInvariant();
        var dot = host.IndexOf('.');
        return dot > 0 && d.Equals(host[(dot + 1)..], StringComparison.Ordinal);
    }

    /// <summary>
    /// 这个地址要不要走邮箱验证码。
    ///
    /// ⚠️ **本机托管的地址必须跳过**，否则是死循环：验证码邮件投进的就是这个信箱，
    /// 而它在验证通过前不允许登录（IMAP / Webmail / API 全部进不去）→ 用户永远拿不到验证码。
    /// 这类地址的授权凭据是**邀请码**（管理员亲自发放），注册即开通。
    /// 只有邮箱托管在别处（例如 AllowedDomains 里放了 gmail.com）时，邮箱验证才真正有意义。
    /// </summary>
    public bool NeedsEmailVerification(string? email) => Policy.RequireEmailVerification && !IsHostedHere(email);

    // ---------------------------------------------------------------- 校验

    public static bool LooksLikeEmail(string? email) =>
        !string.IsNullOrWhiteSpace(email)
        && email.Length <= 254
        && email.Count(c => c == '@') == 1
        && email.IndexOf('@') > 0
        && email.IndexOf('@') < email.Length - 1
        && !email.Any(char.IsWhiteSpace)
        && email.Contains('.');

    /// <summary>密码强度：长度 + 不能纯数字 + 不能与邮箱相同（够用即可，不搞复杂度表演）。</summary>
    public (bool Ok, string Error) CheckPassword(string? password, string email)
    {
        var min = Math.Max(8, Policy.MinPasswordLength);
        if (string.IsNullOrEmpty(password)) return (false, "密码不能为空");
        if (password.Length < min) return (false, $"密码至少需要 {min} 个字符");
        if (password.Length > 200) return (false, "密码过长");
        if (password.All(char.IsDigit)) return (false, "密码不能全是数字");
        if (!string.IsNullOrWhiteSpace(email) && password.Equals(email, StringComparison.OrdinalIgnoreCase))
            return (false, "密码不能与邮箱相同");
        return (true, "");
    }

    private (bool Ok, string Error) CheckDomain(string email)
    {
        var at = email.LastIndexOf('@');
        if (at < 0) return (false, "邮箱地址不合法");
        var domain = email[(at + 1)..].ToLowerInvariant();
        var allowed = Policy.EffectiveDomains(config.Domain);
        if (allowed.Length == 0) return (true, "");
        return allowed.Contains(domain)
            ? (true, "")
            : (false, $"只允许注册 @{string.Join(" / @", allowed)} 的邮箱");
    }

    // ---------------------------------------------------------------- 验证码

    private static string NewCode() => RandomNumberGenerator.GetInt32(0, 1_000_000).ToString("D6");

    private static string HashCode(string code, string salt) =>
        Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(code, Convert.FromBase64String(salt), 60_000, HashAlgorithmName.SHA256, 32));

    private static bool VerifyCode(string code, string hash, string salt)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(
                Convert.FromBase64String(hash),
                Convert.FromBase64String(HashCode(code, salt)));
        }
        catch { return false; }
    }

    private string CreateCode(string email, string purpose, string payload)
    {
        var code = NewCode();
        var record = new VerificationCode
        {
            Email = email,
            Purpose = purpose,
            Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            Payload = payload,
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(Math.Max(1, Policy.CodeMinutes)),
            CreatedAt = DateTimeOffset.UtcNow,
            Attempts = 0,
        };
        record.CodeHash = HashCode(code, record.Salt);
        record.SentAt = DateTimeOffset.UtcNow;
        store.SaveVerificationCode(record);
        return code;
    }

    /// <summary>校验验证码；成功返回 true 并删除该验证码。会处理过期与试错次数。</summary>
    public (bool Ok, string Error, VerificationCode? Record) ConsumeCode(string email, string purpose, string code)
    {
        var record = store.FindVerificationCode(email, purpose);
        if (record is null) return (false, "没有待验证的请求，请重新获取验证码", null);
        if (record.ExpiresAt < DateTimeOffset.UtcNow)
        {
            store.RemoveVerificationCode(email, purpose);
            return (false, "验证码已过期，请重新获取", null);
        }
        if (record.Attempts >= Math.Max(1, Policy.MaxCodeAttempts))
        {
            store.RemoveVerificationCode(email, purpose);
            return (false, "验证码尝试次数过多，已作废，请重新获取", null);
        }
        if (!VerifyCode((code ?? "").Trim(), record.CodeHash, record.Salt))
        {
            var attempts = store.IncrementVerificationAttempts(email, purpose);
            var left = Math.Max(0, Policy.MaxCodeAttempts - attempts);
            Record(email, "", "code-failed", false, $"purpose={purpose} attempts={attempts}");
            return (false, left > 0 ? $"验证码不正确，还可以试 {left} 次" : "验证码已作废，请重新获取", null);
        }
        store.RemoveVerificationCode(email, purpose);
        return (true, "", record);
    }

    // ---------------------------------------------------------------- 注册

    public sealed record RegisterResult(bool Ok, int Status, string Error, bool VerificationRequired, object? Session);

    public RegisterResult Register(RegisterRequest request, string ip, string userAgent)
    {
        var email = (request.Email ?? "").Trim().ToLowerInvariant();

        if (!Policy.Registration.Equals("open", StringComparison.OrdinalIgnoreCase)
            && !Policy.Registration.Equals("invite", StringComparison.OrdinalIgnoreCase))
        {
            Record(email, ip, "register", false, "registration closed");
            return new RegisterResult(false, 403, "本服务器已关闭自助注册，请联系管理员开设账号", false, null);
        }
        if (Policy.Registration.Equals("invite", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(request.InviteCode?.Trim(), Policy.InviteCode.Trim(), StringComparison.Ordinal))
        {
            Record(email, ip, "register", false, "bad invite code");
            return new RegisterResult(false, 403, "邀请码不正确", false, null);
        }
        if (!LooksLikeEmail(email))
        {
            Record(email, ip, "register", false, "bad email");
            return new RegisterResult(false, 400, "邮箱地址不合法", false, null);
        }
        var domain = CheckDomain(email);
        if (!domain.Ok)
        {
            Record(email, ip, "register", false, "domain not allowed");
            return new RegisterResult(false, 400, domain.Error, false, null);
        }
        // 已激活的账号：直接拒绝。**未激活的注册允许重来**（上一次验证码没收到 / 输错太多次），
        // 重来不会覆盖已有密码 —— 密码只由「读到验证码的人」在验证那一步写入。
        var existing = store.FindUserAnyState(email);
        if (existing is not null && existing.Active)
        {
            Record(email, ip, "register", false, "already exists");
            return new RegisterResult(false, 409, "这个邮箱已经注册过了，请直接登录或使用「忘记密码」", false, null);
        }
        if (existing is not null && existing.LastLoginAt is not null)
        {
            // 这一行曾经是正常账号（登录过），现在被管理员停用了。
            // **停用是权威状态**：不能靠「重新注册」把它翻回启用，否则拿到邀请码的人就能推翻管理员的封禁。
            Record(email, ip, "register", false, "account disabled by admin");
            return new RegisterResult(false, 403, "该账号已被管理员停用，请联系管理员", false, null);
        }
        var password = CheckPassword(request.Password, email);
        if (!password.Ok)
        {
            Record(email, ip, "register", false, "weak password");
            return new RegisterResult(false, 400, password.Error, false, null);
        }
        // 限流：同一 IP 每小时最多建成几个账号。
        //
        // ⚠ 这里**只把「真的建出了账号」算进严格配额**，失败尝试（邀请码填错、密码太短、域名不对）
        //   不算 —— 否则一个正常新用户表单填错几次就被挡一小时，而且在 NAT / 手机网络下
        //   会连累同 IP 的其他人（真机验收就撞到过：连续两次运行验收脚本，第二次直接 429）。
        //   失败尝试另有一个宽松上限，避免有人拿邀请码当靶子爆破；审计里两类都记得清清楚楚。
        var perIp = Policy.RegisterPerHourPerIp;
        if (perIp > 0 && store.CountAuthEvents(null, ip, "register", true, 60) >= perIp)
        {
            Record(email, ip, "register", false, "rate limited (ip quota)");
            return new RegisterResult(false, 429, "注册请求过于频繁，请稍后再试", false, null);
        }
        var failLimit = Math.Max(10, perIp * 4);
        if (perIp > 0 && store.CountAuthEvents(null, ip, "register", false, 60) >= failLimit)
        {
            Record(email, ip, "register", false, "rate limited (failed attempts)");
            return new RegisterResult(false, 429, "注册请求过于频繁，请稍后再试", false, null);
        }
        // 同一邮箱也有次数上限（防止有人盯着一个地址反复发验证码）
        if (perIp > 0 && store.CountAuthEvents(email, null, "register", true, 60) >= Math.Max(2, perIp))
        {
            Record(email, ip, "register", false, "email rate limited");
            return new RegisterResult(false, 429, "该邮箱的注册请求过于频繁，请稍后再试", false, null);
        }

        var displayName = string.IsNullOrWhiteSpace(request.DisplayName) ? email.Split('@')[0] : request.DisplayName!.Trim();
        var needsVerify = NeedsEmailVerification(email);

        // 密码哈希先算好，但**先不放用户表**（要验证邮箱时才如此）
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var pendingHash = HashPassword(request.Password!, salt);

        // 先把信箱行建出来（未激活），否则本地投递看不到这个收件人、验证码邮件送不进来。
        // 需要验证时，用户行里的密码是随机不可用值 —— 就算有人抢先用你的邮箱注册，
        // 也无法在这个账号上留下自己的密码；密码只在验证码通过时写入。
        var unusableHash = HashPassword(Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)), salt);
        var created = store.CreateUserWithHash(email, needsVerify ? unusableHash : pendingHash, salt, displayName, active: !needsVerify);
        if (!needsVerify && !created.Active)
        {
            store.SetUserActive(email, true);
            created = store.FindUser(email) ?? created;
        }

        if (!needsVerify)
        {
            var why = IsHostedHere(email) ? "本机托管的信箱，授权凭据是邀请码" : "策略未要求邮箱验证";
            Record(email, ip, "register", true, $"created without email verification（{why}）");
            AppLog.Info($"[账号] 新账号已直接开通（免邮箱验证）：{email} —— {why}");
            return new RegisterResult(true, 201, "", false, NewSession(created, ip, userAgent));
        }

        var payload = JsonSerializer.Serialize(new PendingRegistration
        {
            DisplayName = displayName,
            PasswordHash = pendingHash,
            PasswordSalt = salt,
        });
        var code = CreateCode(email, "register", payload);
        var sent = SendCodeMail(email, code, "注册验证", "register");
        Record(email, ip, "register", true, sent.Ok ? "code sent" : $"code send failed: {sent.Error}");
        if (!sent.Ok)
            return new RegisterResult(false, 502, $"验证邮件发送失败：{sent.Error}", true, null);

        return new RegisterResult(true, 202, "", true, new
        {
            verificationRequired = true,
            email,
            expiresInMinutes = Policy.CodeMinutes,
        });
    }

    /// <summary>校验注册验证码：通过后写入密码并激活账号（等价于注册即登录）。</summary>
    public (bool Ok, int Status, string Error, object? Session) VerifyRegistration(VerifyCodeRequest request, string ip, string userAgent)
    {
        var email = (request.Email ?? "").Trim().ToLowerInvariant();
        if (!LooksLikeEmail(email)) return (false, 400, "邮箱地址不合法", null);

        var user = store.FindUserAnyState(email);
        if (user is null) return (false, 404, "没有待验证的注册，请先提交注册", null);
        if (user.Active) return (false, 409, "这个邮箱已经激活过了，请直接登录", null);

        var (ok, error, record) = ConsumeCode(email, "register", request.Code ?? "");
        if (!ok) return (false, 400, error, null);

        PendingRegistration? pending;
        try
        {
            pending = JsonSerializer.Deserialize<PendingRegistration>(
                record?.Payload ?? "", new JsonSerializerOptions(JsonSerializerDefaults.Web));
        }
        catch { pending = null; }

        if (pending is null || string.IsNullOrEmpty(pending.PasswordHash) || string.IsNullOrEmpty(pending.PasswordSalt))
            return (false, 400, "注册信息已失效，请重新提交注册", null);

        // 到这一步验证码已证明邮箱归属，才把密码写进用户行并激活
        store.CreateUserWithHash(email, pending.PasswordHash, pending.PasswordSalt,
            string.IsNullOrWhiteSpace(pending.DisplayName) ? user.DisplayName : pending.DisplayName, active: false);
        store.SetUserActive(email, true);
        var activated = store.FindUser(email) ?? user;
        Record(email, ip, "register-verify", true, "activated");
        AppLog.Info($"[账号] 新账号已激活：{email}");
        return (true, 201, "", NewSession(activated, ip, userAgent));
    }

    // ---------------------------------------------------------------- 密码重置

    public (bool Ok, string Error) RequestReset(string email, string ip)
    {
        email = (email ?? "").Trim().ToLowerInvariant();
        if (!LooksLikeEmail(email)) return (false, "邮箱地址不合法");
        var user = store.FindUserAnyState(email);
        if (user is null)
        {
            // 不暴露账号是否存在；但仍然记录审计
            Record(email, ip, "reset-request", false, "unknown user");
            return (true, "");
        }
        var limit = Math.Max(2, Policy.ResendPerHourPerEmail);
        if (store.CountAuthEvents(email, null, "reset-request", null, 60) >= limit)
        {
            Record(email, ip, "reset-request", false, "rate limited");
            return (false, "请求过于频繁，请稍后再试");
        }
        var code = CreateCode(email, "reset", "");
        var sent = SendCodeMail(email, code, "重置密码", "reset");
        Record(email, ip, "reset-request", sent.Ok, sent.Ok ? "code sent" : sent.Error);
        return sent.Ok ? (true, "") : (false, $"验证邮件发送失败：{sent.Error}");
    }

    public (bool Ok, int Status, string Error) ResetPassword(ResetPasswordRequest request, string ip)
    {
        var email = (request.Email ?? "").Trim().ToLowerInvariant();
        if (!LooksLikeEmail(email)) return (false, 400, "邮箱地址不合法");
        var check = CheckPassword(request.Password, email);
        if (!check.Ok) return (false, 400, check.Error);

        var (ok, error, _) = ConsumeCode(email, "reset", request.Code ?? "");
        if (!ok) return (false, 400, error);

        try { store.ChangePassword(email, request.Password!); }
        catch (InvalidOperationException) { return (false, 404, "账号不存在"); }

        // 未激活的账号走到这里说明邮箱归属已被证明（验证码在本人手里）→ 顺带激活，
        // 这就是「注册时验证码没收到、卡在未激活」的兜底恢复路径。
        var anyState = store.FindUserAnyState(email);
        var activated = anyState is { Active: false };
        if (activated) store.SetUserActive(email, true);

        // 改密后踢掉所有会话（别人的登录一并失效，这是安全要求）
        var revoked = store.RemoveSessions(email, null);
        Record(email, ip, "reset-ok", true, $"sessions revoked={revoked} activated={activated}");
        AppLog.Info($"[账号] {email} 通过邮件验证码重置了密码{(activated ? "并激活了账号" : "")}，已吊销 {revoked} 个会话。");
        return (true, 200, "");
    }

    /// <summary>重发验证码（注册 / 重置共用）。</summary>
    public (bool Ok, int Status, string Error) ResendCode(string email, string purpose, string ip)
    {
        email = (email ?? "").Trim().ToLowerInvariant();
        if (!LooksLikeEmail(email)) return (false, 400, "邮箱地址不合法");
        if (purpose is not ("register" or "reset")) return (false, 400, "purpose 只能是 register 或 reset");

        var limit = Math.Max(2, Policy.ResendPerHourPerEmail);
        if (store.CountAuthEvents(email, null, "code-sent", null, 60) >= limit)
        {
            Record(email, ip, "code-sent", false, "rate limited");
            return (false, 429, "重发过于频繁，请稍后再试");
        }
        var existing = store.FindVerificationCode(email, purpose);
        if (existing is null) return (false, 404, "没有待验证的请求，请重新发起");

        var code = CreateCode(email, purpose, existing.Payload);
        var sent = SendCodeMail(email, code, purpose == "register" ? "注册验证" : "重置密码", purpose);
        Record(email, ip, "code-sent", sent.Ok, sent.Ok ? "resent" : sent.Error);
        return sent.Ok ? (true, 200, "") : (false, 502, $"验证邮件发送失败：{sent.Error}");
    }

    // ---------------------------------------------------------------- 登录加固

    /// <summary>
    /// 登录失败（Authenticate 返回 null）时该怎么回话，以及审计里写什么原因。
    ///
    /// 原则：**只在用户真的卡住时多说话**。「注册了但没验证完」的人如果只看到「邮箱或密码不正确」，
    /// 会一直以为密码错了 —— 而正确的出路是完成验证或用「忘记密码」。
    /// 其余情形（账号不存在 / 密码错 / 被管理员停用）一律同一句话，不做账号状态探测。
    /// </summary>
    public (int Status, string Error, bool PendingVerification, string AuditReason) LoginFailureHint(string email)
    {
        var any = store.FindUserAnyState(email);
        if (any is null) return (401, "邮箱或密码不正确", false, "unknown user");
        if (any.Active) return (401, "邮箱或密码不正确", false, "bad password");
        if (store.FindVerificationCode(email, "register") is not null)
        {
            return (403,
                "这个邮箱的注册还没完成邮箱验证。请用注册时收到的验证码完成验证，或用「忘记密码」重设密码。",
                true, "pending verification");
        }
        // 被管理员停用（或注册早已过期作废）—— 不区分，避免探测账号状态
        return (401, "邮箱或密码不正确", false, "account not activated or disabled");
    }

    /// <summary>返回锁定剩余秒数；0 表示未锁定。</summary>
    public int LockRemainingSeconds(string email)
    {
        var max = Policy.MaxLoginFailures;
        if (max <= 0) return 0;
        var failures = store.CountAuthEvents(email, null, "login-failed", false, Policy.LockoutMinutes);
        if (failures < max) return 0;
        var recent = store.ListAuthEvents(email, null, "login-failed", max);
        if (recent.Count == 0) return 0;
        var unlockAt = recent[0].At.AddMinutes(Policy.LockoutMinutes);
        var left = (int)Math.Ceiling((unlockAt - DateTimeOffset.UtcNow).TotalSeconds);
        return Math.Max(1, left);
    }

    public object? NewSession(MailUser user, string ip, string userAgent)
    {
        var session = store.CreateSession(user.Email, config.Api.SessionDays);
        store.SetLastLogin(user.Email);
        Record(user.Email, ip, "login-ok", true, userAgent);
        return new
        {
            token = session.Token,
            expiresAt = session.Expires,
            user = new { email = user.Email, displayName = user.DisplayName, role = user.Role, domain = user.Email.Split('@').LastOrDefault() },
        };
    }

    public void Record(string email, string ip, string reason, bool success, string detail = "", string userAgent = "")
        => store.RecordAuthEvent(new AuthEvent
        {
            Email = email ?? "",
            Ip = ip ?? "",
            Reason = reason,
            Success = success,
            Detail = detail,
            UserAgent = userAgent,
        });

    // ---------------------------------------------------------------- 会话 / 资料

    public object SessionsView(string email, string? currentToken) =>
        new
        {
            sessions = store.ListSessions(email).Select(s => new
            {
                tokenPrefix = s.Token.Length > 10 ? s.Token[..10] : s.Token,
                token = s.Token,
                current = !string.IsNullOrEmpty(currentToken) && s.Token == currentToken,
                createdAt = s.CreatedAt,
                expiresAt = s.Expires,
            }),
        };

    public int RevokeSessions(string email, string? keepToken) => store.RemoveSessions(email, keepToken);

    public void UpdateProfile(string email, string? displayName)
    {
        if (displayName is null) return;
        store.UpdateProfile(email, displayName.Trim());
    }

    // ---------------------------------------------------------------- 发信

    /// <summary>把验证码邮件投进出站队列（复用既有的 Mime.Build + QueueOutbound + 投递/重试链路）。</summary>
    private (bool Ok, string Error) SendCodeMail(string to, string code, string title, string purpose)
    {
        try
        {
            var minutes = Math.Max(1, Policy.CodeMinutes);
            var text = new StringBuilder()
                .AppendLine($"你正在{(purpose == "register" ? "注册" : "重置")} WpywMail 账号（{to}）。")
                .AppendLine()
                .AppendLine($"验证码：{code}")
                .AppendLine()
                .AppendLine($"验证码 {minutes} 分钟内有效，最多可尝试 {Math.Max(1, Policy.MaxCodeAttempts)} 次。")
                .AppendLine("如果不是你本人操作，忽略这封邮件即可，你的账号不受影响。")
                .AppendLine()
                .AppendLine($"—— {config.Hostname}")
                .ToString();

            var sender = string.IsNullOrWhiteSpace(config.AdminEmail) ? $"postmaster@{config.Domain}" : config.AdminEmail;
            var raw = Mime.Build(new ComposeRequest(
                sender,
                "WpywMail",
                [to],
                [],
                $"【WpywMail】{title}验证码：{code}",
                text,
                null,
                [],
                MessageId: null,
                InReplyTo: "",
                References: ""), config);

            var message = store.QueueOutbound(sender, [to], $"[WpywMail] {title}验证码", text, raw,
                string.Join(", ", Array.Empty<string>()), "", "", null);
            AppLog.Info($"[账号] 已入队验证码邮件：{to}（{title}，messageId={message.Id}）");
            return (true, "");
        }
        catch (Exception ex)
        {
            AppLog.Error($"[账号] 验证码邮件入队失败：{to} —— {ex.Message}");
            return (false, ex.Message);
        }
    }

    private static string HashPassword(string password, string salt) =>
        Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(salt), 120_000, HashAlgorithmName.SHA256, 32));

    /// <summary>注册待验证时暂存的信息（存进验证码记录的 Payload，验证通过后才写进用户表）。</summary>
    public sealed class PendingRegistration
    {
        public string DisplayName { get; set; } = "";
        public string PasswordHash { get; set; } = "";
        public string PasswordSalt { get; set; } = "";
    }
}
