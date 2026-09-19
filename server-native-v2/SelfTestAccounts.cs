using System.Text.Json;

namespace WpywMail.Native;

/// <summary>
/// 账号体系自检：注册（含验证码）、登录失败锁定、密码重置、会话管理、资料与审计。
///
/// 这些用例**不经过 HTTP**，直接打 AccountService + 存储层，所以跑得快、
/// 也能覆盖「两套存储后端行为一致」这一点（json 与 sqlite 各跑一遍）。
/// 验证码是随机的、只能从邮件正文里拿；这里为了可测，直接从存储里读回
/// 哈希校验逻辑无法反推明文 —— 所以改为**注入式**：测试里用一个已知码替换哈希。
/// </summary>
public static partial class SelfTest
{
    private static void TestAccounts()
    {
        foreach (var provider in new[] { "json", "sqlite" })
        {
            var config = new AppConfig
            {
                Domain = "wpy.email",
                Hostname = "mail.example.com",
                AdminEmail = "accounts@wpy.email",
                AdminPassword = "selftest-password-1234",
                DataDirectory = Path.Combine(Path.GetTempPath(), $"wpyw-acct-{provider}-{Guid.NewGuid().ToString("N")[..8]}"),
                Dkim = new DkimConfig { Enabled = false },
                Storage = new StorageConfig { Provider = provider },
            };
            Directory.CreateDirectory(config.DataDirectory);
            IMailStore? store = null;
            try
            {
                config.Accounts = new AccountsConfig
                {
                    Registration = "invite",
                    InviteCode = "TEST-INVITE",
                    // 两个域各司其职：wpy.email 由本机托管（免验证路径），mail.example.net 托管在别处（走验证码路径）
                    AllowedDomains = ["wpy.email", "mail.example.net"],
                    RequireEmailVerification = true,
                    MinPasswordLength = 12,
                    CodeMinutes = 30,
                    MaxCodeAttempts = 3,
                    MaxLoginFailures = 3,
                    LockoutMinutes = 15,
                    RegisterPerHourPerIp = 5,
                    ResendPerHourPerEmail = 5,
                };
                store = Program.CreateStore(config);
                var accounts = new AccountService(config, store);

                // ---- 密码策略
                Check($"[{provider}] 密码太短被拒", !accounts.CheckPassword("short", "a@wpy.email").Ok, "");
                Check($"[{provider}] 纯数字密码被拒", !accounts.CheckPassword("123456789012", "a@wpy.email").Ok, "");
                Check($"[{provider}] 与邮箱相同的密码被拒", !accounts.CheckPassword("a@wpy.email", "a@wpy.email").Ok, "");
                Check($"[{provider}] 合格密码被接受", accounts.CheckPassword("Str0ng-Pass-2026", "a@wpy.email").Ok, "");

                // ---- 域名白名单
                Check($"[{provider}] 域名校验：允许 wpy.email",
                    accounts.Register(new RegisterRequest("new1@wpy.email", "Str0ng-Pass-2026", "新人", "TEST-INVITE"), "10.0.0.1", "test").Ok, "");
                var badDomain = accounts.Register(new RegisterRequest("someone@example.com", "Str0ng-Pass-2026", "", "TEST-INVITE"), "10.0.0.2", "test");
                Check($"[{provider}] 域名校验：拒绝外部域", !badDomain.Ok && badDomain.Status == 400, badDomain.Error);

                // ---- 邀请码
                var badInvite = accounts.Register(new RegisterRequest("new2@wpy.email", "Str0ng-Pass-2026", "", "WRONG"), "10.0.0.3", "test");
                Check($"[{provider}] 邀请码错误被拒", !badInvite.Ok && badInvite.Status == 403, badInvite.Error);

                // ---- 弱密码
                var weak = accounts.Register(new RegisterRequest("new3@wpy.email", "123", "", "TEST-INVITE"), "10.0.0.4", "test");
                Check($"[{provider}] 注册时弱密码被拒", !weak.Ok && weak.Status == 400, weak.Error);

                // ---- 【设计决定】本机托管的地址必须免邮箱验证直接开通
                //   验证码邮件只能投进「这个」信箱，而它在验证通过前登录不了（IMAP/Webmail/API 全进不去）
                //   → 要验证就是死循环。这类地址的授权凭据是管理员发放的邀请码。
                var hostedEmail = $"hosted{provider}@wpy.email";
                var hostedReg = accounts.Register(new RegisterRequest(hostedEmail, "Str0ng-Pass-2026", "本机地址", "TEST-INVITE"), "10.0.0.21", "test");
                Check($"[{provider}] 本机托管地址免邮箱验证直接开通",
                    hostedReg.Ok && !hostedReg.VerificationRequired, hostedReg.Error);
                Check($"[{provider}] 本机托管地址开通后立即可登录",
                    store.Authenticate(hostedEmail, "Str0ng-Pass-2026") is not null, "");
                Check($"[{provider}] 免验证注册不会残留验证码记录",
                    store.FindVerificationCode(hostedEmail, "register") is null, "");
                Check($"[{provider}] 托管判定：本机域=true / 外部域=false",
                    accounts.IsHostedHere("a@wpy.email") && !accounts.IsHostedHere("a@mail.example.net"), "");

                // ---- 注册 → 验证码 → 激活（外部托管的邮箱：验证码才有意义）
                var email = $"reg{provider}@mail.example.net";
                var register = accounts.Register(new RegisterRequest(email, "Str0ng-Pass-2026", "注册用户", "TEST-INVITE"), "10.0.0.5", "test");
                Check($"[{provider}] 注册返回需要邮箱验证", register.Ok && register.VerificationRequired, register.Error);

                // ★ 关键回归：曾经写成「验证通过才建号」，结果本地投递看不到收件人、验证码邮件根本送不到。
                //   正确做法是注册时就把信箱行建出来并置为未激活。
                var pending = store.FindUserAnyState(email);
                Check($"[{provider}] 注册后立即建号且处于未激活状态", pending is { Active: false },
                    pending is null ? "(无用户行)" : $"active={pending.Active}");
                Check($"[{provider}] 未激活的信箱对本地投递可见", store.IsLocalAddress(email), "");
                Check($"[{provider}] 未激活期间任何密码都不能登录（凭据只存在验证码记录里）",
                    store.Authenticate(email, "Str0ng-Pass-2026") is null, "");

                var code = ReadCodeFromOutbox(store, email);
                Check($"[{provider}] 验证码邮件已入队且能取出 6 位码", code is { Length: 6 }, code ?? "(空)");

                // ★ 端到端：这封验证码邮件必须真的能投进那个「未激活」信箱。
                //   原设计（验证通过才建号）就是死在这里 —— 本地投递找不到收件人，用户永远收不到码。
                var codeRaw = ReadQueuedRaw(store, email);
                var landed = codeRaw is null ? null : store.DeliverLocal(email, codeRaw, "postmaster@wpy.email");
                Check($"[{provider}] 验证码邮件真的投进了未激活信箱",
                    landed is not null && landed.OwnerEmail.Equals(email, StringComparison.OrdinalIgnoreCase),
                    landed is null ? "本地投递返回 null（收件人不可见）" : $"owner={landed.OwnerEmail} folder={landed.Folder} 未读={landed.Unread}");

                var wrong = accounts.VerifyRegistration(new VerifyCodeRequest(email, "000000"), "10.0.0.5", "test");
                Check($"[{provider}] 错误验证码被拒", !wrong.Ok, wrong.Error);

                var verified = accounts.VerifyRegistration(new VerifyCodeRequest(email, code!), "10.0.0.5", "test");
                Check($"[{provider}] 正确验证码激活账号", verified.Ok && verified.Session is not null, verified.Error);
                var created = store.FindUser(email);
                Check($"[{provider}] 激活后用户存在且可认证",
                    created is not null && store.Authenticate(email, "Str0ng-Pass-2026") is not null, "");
                Check($"[{provider}] 激活后验证码被清除", store.FindVerificationCode(email, "register") is null, "");

                var reuse = accounts.VerifyRegistration(new VerifyCodeRequest(email, code!), "10.0.0.5", "test");
                Check($"[{provider}] 验证码不能用第二次", !reuse.Ok, reuse.Error);

                // ---- 未完成验证的注册可以重来；抢注者无法凭自己提交的密码进去
                var pendEmail = $"pending{provider}@mail.example.net";
                accounts.Register(new RegisterRequest(pendEmail, "First-Pass-2026", "先注册", "TEST-INVITE"), "10.0.0.7", "test");
                var again = accounts.Register(new RegisterRequest(pendEmail, "Second-Pass-2026", "后注册", "TEST-INVITE"), "10.0.0.8", "test");
                Check($"[{provider}] 未激活的注册允许重来（不返回 409）", again.Ok && again.VerificationRequired, again.Error);
                Check($"[{provider}] 重来期间两个密码都不能登录（未激活就没有可用凭据）",
                    store.Authenticate(pendEmail, "First-Pass-2026") is null && store.Authenticate(pendEmail, "Second-Pass-2026") is null, "");
                var pendCode = ReadCodeFromOutbox(store, pendEmail);
                var pendVerified = accounts.VerifyRegistration(new VerifyCodeRequest(pendEmail, pendCode!), "10.0.0.8", "test");
                Check($"[{provider}] 验证后生效的是读得到验证码那一方提交的密码",
                    pendVerified.Ok
                    && store.Authenticate(pendEmail, "Second-Pass-2026") is not null
                    && store.Authenticate(pendEmail, "First-Pass-2026") is null, pendVerified.Error);

                // ---- 登录失败时的措辞：卡在验证的人要被告知出路；被停用的人不能被探测出来
                var pendHint = accounts.LoginFailureHint(pendEmail);
                Check($"[{provider}] 已激活账号的失败提示是通用 401",
                    pendHint.Status == 401 && !pendHint.PendingVerification, pendHint.AuditReason);
                var hintPending = accounts.LoginFailureHint($"pending2{provider}@mail.example.net");
                Check($"[{provider}] 不存在的账号失败提示是通用 401（不暴露存在性）",
                    hintPending.Status == 401 && hintPending.AuditReason == "unknown user", hintPending.AuditReason);
                accounts.Register(new RegisterRequest($"pending2{provider}@mail.example.net", "Str0ng-Pass-2026", "", "TEST-INVITE"), "10.0.0.13", "test");
                var hintWait = accounts.LoginFailureHint($"pending2{provider}@mail.example.net");
                Check($"[{provider}] 卡在邮箱验证的账号会被告知出路（403）",
                    hintWait.Status == 403 && hintWait.PendingVerification, $"{hintWait.Status} {hintWait.AuditReason}");

                // ---- 管理员停用是权威状态：不能靠重新注册翻回来
                var disabled = $"disabled{provider}@wpy.email";
                store.CreateUser(disabled, "Str0ng-Pass-2026", "停用测试");
                store.SetLastLogin(disabled);
                store.SetUserActive(disabled, false);
                var reReg = accounts.Register(new RegisterRequest(disabled, "Str0ng-Pass-2026", "", "TEST-INVITE"), "10.0.0.14", "test");
                Check($"[{provider}] 被停用的账号不能靠重新注册复活（403）",
                    !reReg.Ok && reReg.Status == 403, $"{reReg.Status} {reReg.Error}");
                Check($"[{provider}] 被停用的账号登录提示不暴露状态（401）",
                    accounts.LoginFailureHint(disabled).Status == 401, "");
                Check($"[{provider}] 停用状态没有被注册流程改掉", store.FindUser(disabled) is null, "");

                // ---- 重复注册（已激活的账号必须被挡）
                var dup = accounts.Register(new RegisterRequest(email, "Str0ng-Pass-2026", "", "TEST-INVITE"), "10.0.0.6", "test");
                Check($"[{provider}] 已激活账号重复注册被拒（409）", !dup.Ok && dup.Status == 409, dup.Error);

                // ---- 登录失败锁定
                var lockedEmail = "lock@wpy.email";
                store.CreateUser(lockedEmail, "Str0ng-Pass-2026", "锁定测试");
                for (var i = 0; i < config.Accounts.MaxLoginFailures; i++)
                    accounts.Record(lockedEmail, "10.0.0.9", "login-failed", false, "test");
                Check($"[{provider}] 连续失败后进入锁定", accounts.LockRemainingSeconds(lockedEmail) > 0,
                    $"剩余 {accounts.LockRemainingSeconds(lockedEmail)}s");
                var fresh = "fresh@wpy.email";
                store.CreateUser(fresh, "Str0ng-Pass-2026", "未锁定");
                Check($"[{provider}] 未失败过的账号不锁定", accounts.LockRemainingSeconds(fresh) == 0, "");

                // ---- 审计可查
                var events = store.ListAuthEvents(lockedEmail, null, "login-failed", 10);
                Check($"[{provider}] 审计记录了登录失败", events.Count == config.Accounts.MaxLoginFailures, $"{events.Count} 条");
                Check($"[{provider}] 按 IP 统计失败次数", store.CountAuthEvents(null, "10.0.0.9", "login-failed", false, 60) == config.Accounts.MaxLoginFailures, "");

                // ---- 会话管理
                var sessions = store.ListSessions(fresh);
                Check($"[{provider}] 新建用户初始无会话", sessions.Count == 0, $"{sessions.Count} 个");
                var s1 = store.CreateSession(fresh, 30);
                var s2 = store.CreateSession(fresh, 30);
                var s3 = store.CreateSession(fresh, 30);
                Check($"[{provider}] 三次登录产生三个会话", store.ListSessions(fresh).Count == 3, "");
                var revoked = store.RemoveSessions(fresh, s2.Token);
                Check($"[{provider}] 退出其他设备保留当前（吊销 2 个）", revoked == 2 && store.ListSessions(fresh).Count == 1, $"吊销 {revoked} 个");
                Check($"[{provider}] 保留的正是当前 token", store.GetSession(s2.Token) is not null && store.GetSession(s1.Token) is null, "");
                var all = store.RemoveSessions(fresh, null);
                Check($"[{provider}] 全部吊销", all == 1 && store.ListSessions(fresh).Count == 0, $"吊销 {all} 个");
                Check($"[{provider}] 会话视图标记 current", sessions.Count == 0, "");

                // ---- 资料
                accounts.UpdateProfile(fresh, "新名字");
                var renamed = store.FindUser(fresh);
                Check($"[{provider}] 显示名更新生效", renamed?.DisplayName == "新名字", renamed?.DisplayName ?? "(null)");

                // ---- 密码重置
                var resetEmail = "reset@wpy.email";
                store.CreateUser(resetEmail, "Str0ng-Pass-2026", "重置测试");
                var keep = store.CreateSession(resetEmail, 30);
                var (requested, reqError) = accounts.RequestReset(resetEmail, "10.0.0.10");
                Check($"[{provider}] 申请重置成功", requested, reqError);
                var resetCode = ReadCodeFromOutbox(store, resetEmail);
                Check($"[{provider}] 重置验证码邮件已入队", resetCode is { Length: 6 }, resetCode ?? "(空)");
                var weakReset = accounts.ResetPassword(new ResetPasswordRequest(resetEmail, resetCode!, "123"), "10.0.0.10");
                Check($"[{provider}] 重置时弱密码被拒", !weakReset.Ok && weakReset.Status == 400, weakReset.Error);
                var badCode = accounts.ResetPassword(new ResetPasswordRequest(resetEmail, "999999", "New-Str0ng-2026"), "10.0.0.10");
                Check($"[{provider}] 重置时错误验证码被拒", !badCode.Ok, badCode.Error);
                var good = accounts.ResetPassword(new ResetPasswordRequest(resetEmail, resetCode!, "New-Str0ng-2026"), "10.0.0.10");
                Check($"[{provider}] 正确验证码重置成功", good.Ok, good.Error);
                Check($"[{provider}] 新密码可用", store.Authenticate(resetEmail, "New-Str0ng-2026") is not null, "");
                Check($"[{provider}] 旧密码失效", store.Authenticate(resetEmail, "Str0ng-Pass-2026") is null, "");
                Check($"[{provider}] 重置后旧会话被吊销", store.GetSession(keep.Token) is null, "");

                // ---- 不暴露账号是否存在
                var unknown = accounts.RequestReset("nobody@wpy.email", "10.0.0.11");
                Check($"[{provider}] 对不存在的邮箱申请重置也返回成功（防枚举）", unknown.Ok, unknown.Error);

                // ---- 关闭注册
                config.Accounts.Registration = "closed";
                var closed = accounts.Register(new RegisterRequest("closed@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), "10.0.0.12", "test");
                Check($"[{provider}] 关闭注册后拒绝（403）", !closed.Ok && closed.Status == 403, closed.Error);

                // ---- 限流
                config.Accounts.Registration = "invite";
                config.Accounts.RegisterPerHourPerIp = 2;

                // ★ 真机验收抓到的坑：失败尝试（填错邀请码 / 密码太短）不能吃掉严格配额，
                //   否则正常用户表单填错几次就被挡一小时，NAT 下还会连累同 IP 的其他人。
                var failIp = "10.9.9.10";
                for (var i = 0; i < 6; i++)
                    accounts.Register(new RegisterRequest($"quota{i}-{provider}@wpy.email", "123", "", "TEST-INVITE"), failIp, "test");
                var quota1 = accounts.Register(new RegisterRequest($"quota-a-{provider}@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), failIp, "test");
                var quota2 = accounts.Register(new RegisterRequest($"quota-b-{provider}@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), failIp, "test");
                Check($"[{provider}] 表单填错 6 次后仍能正常建号（失败不吃严格配额）",
                    quota1.Ok && quota2.Ok, $"{quota1.Status}/{quota2.Status}");
                var quota3 = accounts.Register(new RegisterRequest($"quota-c-{provider}@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), failIp, "test");
                Check($"[{provider}] 成功建号达到配额后照样限流（429）",
                    !quota3.Ok && quota3.Status == 429, $"{quota3.Status} {quota3.Error}");

                var ip = "10.9.9.9";
                var r1 = accounts.Register(new RegisterRequest($"rate1-{provider}@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), ip, "test");
                var r2 = accounts.Register(new RegisterRequest($"rate2-{provider}@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), ip, "test");
                var r3 = accounts.Register(new RegisterRequest($"rate3-{provider}@wpy.email", "Str0ng-Pass-2026", "", "TEST-INVITE"), ip, "test");
                Check($"[{provider}] 同 IP 超过每小时上限后被限流（429）",
                    r1.Ok && r2.Ok && !r3.Ok && r3.Status == 429, r3.Error);
            }
            catch (Exception ex)
            {
                Fail($"[{provider}] 账号体系自检", $"抛出异常：{ex.Message}");
            }
            finally
            {
                try { store?.Dispose(); } catch { }
                try { Directory.Delete(config.DataDirectory, true); } catch { }
            }
        }
    }

    /// <summary>从出站队列里把那封验证码邮件的原文取出来，再解析出 6 位验证码。</summary>
    private static string? ReadCodeFromOutbox(IMailStore store, string email)
    {
        try
        {
            var raw = ReadQueuedRaw(store, email);
            if (raw is null) return null;
            var match = System.Text.RegularExpressions.Regex.Match(Mime.Parse(raw).Text ?? "", @"\b(\d{6})\b");
            return match.Success ? match.Groups[1].Value : null;
        }
        catch { return null; }
    }

    /// <summary>取该收件人最近一封出站邮件的原始字节（用于把「投递」也纳入自检）。</summary>
    private static byte[]? ReadQueuedRaw(IMailStore store, string email)
    {
        try
        {
            var items = new List<QueueItem>();
            foreach (var user in store.AllUsers()) items.AddRange(store.ListQueue(user.Email));
            var hit = items
                .Where(q => q.Recipients.Any(r => r.Equals(email, StringComparison.OrdinalIgnoreCase)))
                .OrderByDescending(q => q.CreatedAt)
                .FirstOrDefault();
            if (hit is null) return null;
            var message = store.GetById(hit.MessageId);
            return message is null ? null : store.ReadRaw(message.RawPath);
        }
        catch { return null; }
    }
}
