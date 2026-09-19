using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace WpywMail.Native;

/// <summary>
/// 管理/客户端 API（默认只监听 127.0.0.1，供 Webmail 与桌面客户端经反向代理访问）。
///
/// 认证：POST /api/login 换取 token，之后带 Authorization: Bearer &lt;token&gt;。
/// 会话落盘（sessions.json），因此重启服务不会把已登录的客户端踢掉。
///
/// 端点一览见 README.md；v1 的 /api/login、/api/messages、/api/send、/api/config、
/// /api/me、/api/logout、/api/account/password、/api/admin/users 全部保持兼容。
/// </summary>
public sealed class ApiServer
{
    private readonly AppConfig config;
    private readonly IMailStore store;
    private readonly AccountService accounts;
    private readonly HttpListener listener = new();
    /// <summary>可选的公网监听（只放账号类接口，见 <see cref="IsPublicAccountRoute"/>）。为空表示不开。</summary>
    private readonly HttpListener? publicListener = null;
    private readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public ApiServer(AppConfig config, IMailStore store)
    {
        this.config = config;
        this.store = store;
        this.accounts = new AccountService(config, store);
        listener.Prefixes.Add(config.HttpPrefix);

        // 公网监听（需要在 Windows 里先给这个前缀绑定证书：netsh http add sslcert hostnameport=...）
        if (!string.IsNullOrWhiteSpace(config.Api.PublicPrefix))
        {
            publicListener = new HttpListener();
            publicListener.Prefixes.Add(config.Api.PublicPrefix);
        }
    }

    /// <summary>
    /// 公网监听**只**放行「账号相关」的接口：注册、验证码、找回密码、登录、改密、会话与资料。
    /// 邮件读写（/api/messages、/api/send、/api/queue、/api/watch、/api/drafts）与管理接口
    /// （/api/admin/*）**一律不在公网暴露** —— 那些只能从回环/受控网络访问。
    /// 这是刻意做窄的暴露面：客户端要在公网自助注册与改密码，但读信发信走 IMAP/SMTP。
    /// </summary>
    public static bool IsPublicAccountRoute(string path, string method) => method switch
    {
        "GET" => path is "/api/health" or "/api/version" or "/api/auth/policy"
                 or "/api/me" or "/api/account/sessions" or "/api/account/audit",
        "POST" => path is "/api/login" or "/api/logout" or "/api/register" or "/api/register/verify"
                  or "/api/register/resend" or "/api/auth/forgot" or "/api/auth/reset"
                  or "/api/account/password" or "/api/account/sessions/revoke",
        "PATCH" => path is "/api/account/profile",
        _ => false,
    };

    /// <summary>客户端 IP（本机调用时就是回环地址；审计与限流用）。</summary>
    private static string ClientIp(HttpListenerRequest request) =>
        request.RemoteEndPoint?.Address?.ToString() ?? "";

    private static string UserAgent(HttpListenerRequest request) =>
        request.UserAgent ?? "";

    public async Task RunAsync(CancellationToken token)
    {
        listener.Start();
        AppLog.Info($"[接口] 已监听：{config.HttpPrefix}");

        // 公网监听走同一套处理器，靠 IsPublicAccountRoute 把路径收窄到账号类接口
        if (publicListener is not null)
        {
            try
            {
                publicListener.Start();
                AppLog.Info($"[接口] 公网账号入口已监听：{config.Api.PublicPrefix}"
                    + "（只放注册/验证/找回密码/登录/改密/会话资料；邮件与管理接口仍只在回环）");
                _ = Task.Run(async () =>
                {
                    while (!token.IsCancellationRequested)
                    {
                        var context = await publicListener.GetContextAsync().WaitAsync(token);
                        _ = Task.Run(() => SafeHandleAsync(context, isPublic: true), token);
                    }
                }, token);
            }
            catch (Exception ex)
            {
                AppLog.Error($"[接口] 公网账号入口启动失败：{ex.Message}"
                    + "（HTTPS 前缀需要先用 netsh http add sslcert hostnameport=<host:port> 绑定证书）");
            }
        }

        try
        {
            while (!token.IsCancellationRequested)
            {
                var context = await listener.GetContextAsync().WaitAsync(token);
                _ = Task.Run(() => SafeHandleAsync(context), token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { AppLog.Error($"[接口] 监听异常：{ex.Message}"); }
        finally
        {
            listener.Stop();
            try { publicListener?.Stop(); } catch { }
        }
    }

    private async Task SafeHandleAsync(HttpListenerContext context, bool isPublic = false)
    {
        try { await HandleAsync(context, isPublic); }
        catch (Exception ex)
        {
            AppLog.Error($"[接口] 未处理异常：{ex.Message}");
            try { await Reply(context.Response, new { error = "服务器内部错误" }, 500); } catch { }
        }
    }

    private async Task HandleAsync(HttpListenerContext context, bool isPublic = false)
    {
        var request = context.Request;
        var response = context.Response;
        response.Headers["Access-Control-Allow-Origin"] = config.Api.CorsOrigin;
        response.Headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
        response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS";
        response.Headers["Access-Control-Expose-Headers"] = "Content-Disposition";

        if (request.HttpMethod == "OPTIONS") { response.StatusCode = 204; response.Close(); return; }

        var path = (request.Url?.AbsolutePath ?? "/").TrimEnd('/');
        var method = request.HttpMethod.ToUpperInvariant();

        // 公网入口：白名单之外的路径一律当作「不存在」，不给探测者任何信息
        if (isPublic && !IsPublicAccountRoute(path, method))
        {
            AppLog.Warn($"[接口] 公网入口拒绝：{method} {request.Url?.PathAndQuery}（来自 {ClientIp(request)}）");
            await Reply(response, new { error = "接口不存在" }, 404);
            return;
        }

        AppLog.Info($"[接口] {method} {request.Url?.PathAndQuery}");

        // ---- 无需认证 ----
        if (path is "/api/health" && method == "GET")
        {
            await Reply(response, new { ok = true, service = "wpyw.mail.native", version = BuildInfo.Version, domain = config.Domain, hostname = config.Hostname });
            return;
        }
        if (path is "/api/version" && method == "GET")
        {
            await Reply(response, new { version = BuildInfo.Version, domain = config.Domain, hostname = config.Hostname, dkim = config.Dkim.Enabled });
            return;
        }
        if (path is "/api/login" && method == "POST")
        {
            await LoginAsync(request, response);
            return;
        }

        // ---- 账号体系：无需认证 ----
        if (path is "/api/auth/policy" && method == "GET")
        {
            await Reply(response, accounts.PolicyView());
            return;
        }
        if (path is "/api/register" && method == "POST")
        {
            var body = await ReadJsonAsync<RegisterRequest>(request);
            if (body is null) { await Reply(response, new { error = "请求体不是合法 JSON" }, 400); return; }
            var result = accounts.Register(body, ClientIp(request), UserAgent(request));
            await Reply(response, result.Ok
                ? new { ok = true, verificationRequired = result.VerificationRequired, session = result.Session,
                        email = body.Email?.Trim().ToLowerInvariant(),
                        expiresInMinutes = result.VerificationRequired ? config.Accounts.CodeMinutes : (int?)null }
                : new { error = result.Error }, result.Status);
            return;
        }
        if (path is "/api/register/verify" && method == "POST")
        {
            var body = await ReadJsonAsync<VerifyCodeRequest>(request);
            if (body is null) { await Reply(response, new { error = "请求体不是合法 JSON" }, 400); return; }
            var (ok, status, error, newSession) = accounts.VerifyRegistration(body, ClientIp(request), UserAgent(request));
            await Reply(response, ok ? new { ok = true, session = newSession } : new { error }, status);
            return;
        }
        if (path is "/api/register/resend" && method == "POST")
        {
            var body = await ReadJsonAsync<Dictionary<string, string>>(request) ?? [];
            var email = body.GetValueOrDefault("email") ?? "";
            var purpose = body.TryGetValue("purpose", out var p) && !string.IsNullOrWhiteSpace(p) ? p : "register";
            var (ok, status, error) = accounts.ResendCode(email, purpose, ClientIp(request));
            await Reply(response, ok ? new { ok = true } : new { error }, status);
            return;
        }
        if (path is "/api/auth/forgot" && method == "POST")
        {
            var body = await ReadJsonAsync<Dictionary<string, string>>(request) ?? [];
            var email = body.GetValueOrDefault("email") ?? "";
            var (ok, error) = accounts.RequestReset(email, ClientIp(request));
            // 成功时也统一返回 ok：不暴露「这个邮箱是否存在」
            await Reply(response, ok ? new { ok = true, expiresInMinutes = config.Accounts.CodeMinutes } : new { error },
                ok ? 200 : 429);
            return;
        }
        if (path is "/api/auth/reset" && method == "POST")
        {
            var body = await ReadJsonAsync<ResetPasswordRequest>(request);
            if (body is null) { await Reply(response, new { error = "请求体不是合法 JSON" }, 400); return; }
            var (ok, status, error) = accounts.ResetPassword(body, ClientIp(request));
            await Reply(response, ok ? new { ok = true } : new { error }, status);
            return;
        }

        // ---- 以下都需要认证 ----
        var token = ExtractToken(request);
        var session = store.GetSession(token);
        var user = session is null ? null : store.FindUser(session.Email);
        if (user is null)
        {
            await Reply(response, new { error = "登录已失效，请重新登录" }, 401);
            return;
        }

        try
        {
            switch (path)
            {
                case "/api/logout" when method == "POST":
                    store.RemoveSession(token!);
                    await Reply(response, new { ok = true });
                    return;

                case "/api/me" when method == "GET":
                    await Reply(response, new { user = Project(user), stats = store.Stats(user.Email) });
                    return;

                case "/api/config" when method == "GET":
                    await Reply(response, new
                    {
                        domain = config.Domain,
                        hostname = config.Hostname,
                        account = user.Email,
                        protocols = new { smtp = config.SmtpPort, submission = config.SubmissionPort, api = config.HttpPrefix, tls = config.Smtp.AdvertiseStartTls },
                        features = new { dkim = config.Dkim.Enabled, attachments = true, watch = true, drafts = true },
                    });
                    return;

                case "/api/messages" when method == "GET":
                    await ListMessagesAsync(request, response, user);
                    return;

                case "/api/send" when method == "POST":
                    await SendAsync(request, response, user);
                    return;

                case "/api/drafts" when method == "POST":
                    await SaveDraftAsync(request, response, user);
                    return;

                case "/api/queue" when method == "GET":
                    await Reply(response, new
                    {
                        queue = store.ListQueue(user.Email).Select(x => new
                        {
                            x.Id, x.MessageId, x.Recipients, x.Attempts, x.Status, x.LastError, x.LastCode,
                            nextAttempt = x.NextAttempt, createdAt = x.CreatedAt, lastAttemptAt = x.LastAttemptAt,
                        }),
                    });
                    return;

                case "/api/watch" when method == "GET":
                    await WatchAsync(request, response, user);
                    return;

                case "/api/account/password" when method == "POST":
                    await ChangePasswordAsync(request, response, user);
                    return;

                case "/api/account/profile" when method == "PATCH":
                    await UpdateProfileAsync(request, response, user);
                    return;

                case "/api/account/sessions" when method == "GET":
                    await Reply(response, accounts.SessionsView(user.Email, token));
                    return;

                case "/api/account/sessions/revoke" when method == "POST":
                    await RevokeSessionsAsync(request, response, user, token);
                    return;

                case "/api/account/audit" when method == "GET":
                    {
                        var limit = int.TryParse(request.QueryString["limit"], out var l) ? l : 50;
                        await Reply(response, new
                        {
                            events = store.ListAuthEvents(user.Email, null, null, limit).Select(ProjectAudit),
                        });
                        return;
                    }

                case "/api/admin/audit" when method == "GET":
                    {
                        if (user.Role != "admin") { await Reply(response, new { error = "需要管理员权限" }, 403); return; }
                        var limit = int.TryParse(request.QueryString["limit"], out var l) ? l : 100;
                        var email = request.QueryString["email"];
                        var ipFilter = request.QueryString["ip"];
                        var reason = request.QueryString["reason"];
                        await Reply(response, new
                        {
                            events = store.ListAuthEvents(email, ipFilter, reason, limit).Select(ProjectAudit),
                        });
                        return;
                    }

                case "/api/admin/users":
                    if (user.Role != "admin") { await Reply(response, new { error = "需要管理员权限" }, 403); return; }
                    await AdminUsersAsync(request, response, method);
                    return;
            }

            // /api/messages/{id}...
            if (path.StartsWith("/api/messages/", StringComparison.OrdinalIgnoreCase))
            {
                await MessageRouteAsync(request, response, user, path["/api/messages/".Length..], method);
                return;
            }
            if (path.StartsWith("/api/queue/", StringComparison.OrdinalIgnoreCase))
            {
                var id = path["/api/queue/".Length..];
                if (id.EndsWith("/retry", StringComparison.OrdinalIgnoreCase) && method == "POST")
                {
                    store.RetryQueueItem(user.Email, id[..^"/retry".Length]);
                    await Reply(response, new { ok = true });
                    return;
                }
            }
            if (path.StartsWith("/api/admin/users/", StringComparison.OrdinalIgnoreCase))
            {
                if (user.Role != "admin") { await Reply(response, new { error = "需要管理员权限" }, 403); return; }
                await AdminUserPatchAsync(request, response, Uri.UnescapeDataString(path["/api/admin/users/".Length..]), method);
                return;
            }

            await Reply(response, new { error = "接口不存在" }, 404);
        }
        catch (InvalidOperationException ex)
        {
            await Reply(response, new { error = ex.Message }, 400);
        }
        catch (Exception ex)
        {
            AppLog.Error($"[接口] {method} {path}：{ex.Message}");
            await Reply(response, new { error = ex.Message }, 500);
        }
    }

    // ---------------------------------------------------------------- 认证

    /// <summary>
    /// 登录。相比 v2.0.x 增加了三件事：
    ///   ① 失败计数与临时锁定（同一账号在窗口内连续失败到阈值即锁定，返回 423 与剩余秒数）；
    ///   ② 审计（成功/失败/锁定都记 IP 与 UA，便于排查与限流）；
    ///   ③ 成功时更新 lastLoginAt 并签发会话。
    /// 对外错误信息统一为「邮箱或密码不正确」，真实原因只进审计，避免账号枚举。
    /// </summary>
    private async Task LoginAsync(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJsonAsync<LoginRequest>(request);
        var ip = ClientIp(request);
        var agent = UserAgent(request);
        if (body is null || string.IsNullOrWhiteSpace(body.Email) || string.IsNullOrEmpty(body.Password))
        {
            await Reply(response, new { error = "请提供 email 与 password" }, 400);
            return;
        }

        var email = body.Email.Trim().ToLowerInvariant();

        var locked = accounts.LockRemainingSeconds(email);
        if (locked > 0)
        {
            accounts.Record(email, ip, "login-locked", false, $"remaining={locked}s", agent);
            AppLog.Warn($"[接口] 登录被拒（锁定中）：{email}，剩余 {locked}s");
            await Reply(response, new { error = $"失败次数过多，账号已临时锁定，请 {Math.Ceiling(locked / 60.0)} 分钟后再试", retryAfterSeconds = locked }, 423);
            return;
        }

        var user = store.Authenticate(email, body.Password);
        if (user is null)
        {
            // 失败原因只进审计；对外是否多说一句，由 AccountService 判断（见 LoginFailureHint）
            var hint = accounts.LoginFailureHint(email);
            accounts.Record(email, ip, "login-failed", false, hint.AuditReason, agent);
            var failures = store.CountAuthEvents(email, null, "login-failed", false, config.Accounts.LockoutMinutes);
            AppLog.Warn($"[接口] 登录失败：{email}（{hint.AuditReason}，{failures}/{config.Accounts.MaxLoginFailures}）");
            await Reply(response, new { error = hint.Error, pendingVerification = hint.PendingVerification }, hint.Status);
            return;
        }

        var session = accounts.NewSession(user, ip, agent);
        await Reply(response, session!);
    }

    private static string? ExtractToken(HttpListenerRequest request)
    {
        var header = request.Headers["Authorization"];
        if (string.IsNullOrWhiteSpace(header)) return null;
        return header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase) ? header["Bearer ".Length..].Trim() : header.Trim();
    }

    // ---------------------------------------------------------------- 邮件列表与详情

    private static object Project(MailUser user) => new
    {
        email = user.Email,
        displayName = user.DisplayName,
        role = user.Role,
        active = user.Active,
        createdAt = user.CreatedAt,
        lastLoginAt = user.LastLoginAt,
        domain = user.Email.Split('@').LastOrDefault(),
    };

    private async Task ListMessagesAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var query = request.QueryString;
        var folder = query["folder"] ?? "inbox";
        var search = query["q"] ?? "";
        var unreadOnly = query["unread"] is "1" or "true";
        var starredOnly = query["starred"] is "1" or "true";
        var limit = int.TryParse(query["limit"], out var parsedLimit) ? Math.Clamp(parsedLimit, 1, 500) : 100;
        var offset = int.TryParse(query["offset"], out var parsedOffset) ? Math.Max(0, parsedOffset) : 0;

        var (total, items) = store.ListMessagesPage(user.Email, folder, search, unreadOnly, starredOnly, limit, offset);
        var page = items.Select(Summary).ToArray();
        await Reply(response, new { total, offset, limit, messages = page });
    }

    private static object Summary(MailMessage message) => new
    {
        message.Id,
        message.Folder,
        message.From,
        message.To,
        message.Cc,
        message.Subject,
        message.Date,
        message.ReceivedAt,
        message.Unread,
        message.Starred,
        message.DeliveryStatus,
        message.LastError,
        message.Size,
        attachmentCount = message.Attachments.Count,
        hasAttachments = message.Attachments.Count > 0,
        preview = Preview(message.Text.Length > 0 ? message.Text : StripTags(message.Html)),
    };

    private static string Preview(string text)
    {
        var flat = (text ?? "").Replace("\r", " ").Replace("\n", " ").Trim();
        return flat.Length <= 140 ? flat : flat[..140] + "…";
    }

    private static string StripTags(string html)
    {
        if (string.IsNullOrEmpty(html)) return "";
        var builder = new StringBuilder(html.Length);
        var inside = false;
        foreach (var c in html)
        {
            if (c == '<') { inside = true; continue; }
            if (c == '>') { inside = false; continue; }
            if (!inside) builder.Append(c);
        }
        return builder.ToString();
    }

    private async Task MessageRouteAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user, string rest, string method)
    {
        var segments = rest.Split('/', StringSplitOptions.RemoveEmptyEntries);
        if (segments.Length == 0) { await Reply(response, new { error = "缺少邮件 id" }, 400); return; }
        var id = Uri.UnescapeDataString(segments[0]);
        var message = store.GetMessage(user.Email, id);
        if (message is null) { await Reply(response, new { error = "邮件不存在" }, 404); return; }

        // /api/messages/{id}/raw  或  /api/messages/{id}/attachments/{index}
        if (segments.Length >= 2)
        {
            if (segments[1].Equals("raw", StringComparison.OrdinalIgnoreCase) && method == "GET")
            {
                var bytes = store.ReadRaw(message.RawPath);
                await ReplyBinary(response, bytes, "message/rfc822", $"{Sanitize(message.Subject)}.eml");
                return;
            }
            if (segments[1].Equals("attachments", StringComparison.OrdinalIgnoreCase) && method == "GET")
            {
                if (segments.Length < 3 || !int.TryParse(segments[2], out var index) ||
                    index < 0 || index >= message.Attachments.Count)
                {
                    await Reply(response, new { error = "附件不存在" }, 404);
                    return;
                }
                var attachment = message.Attachments[index];
                var data = store.ReadAttachment(attachment.StoredAs);
                await ReplyBinary(response, data, attachment.ContentType, Sanitize(attachment.FileName));
                return;
            }
            await Reply(response, new { error = "接口不存在" }, 404);
            return;
        }

        switch (method)
        {
            case "GET":
            {
                var markRead = !string.Equals(request.QueryString["markRead"], "false", StringComparison.OrdinalIgnoreCase);
                if (markRead && message.Unread) store.MarkRead(user.Email, id, true);
                await Reply(response, new { message = Detail(message, markRead) });
                return;
            }
            case "PATCH":
            {
                var body = await ReadJsonAsync<Dictionary<string, JsonElement>>(request) ?? [];
                if (body.TryGetValue("unread", out var unread) && unread.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    store.MarkRead(user.Email, id, !unread.GetBoolean());
                if (body.TryGetValue("read", out var read) && read.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    store.MarkRead(user.Email, id, read.GetBoolean());
                if (body.TryGetValue("starred", out var starred) && starred.ValueKind is JsonValueKind.True or JsonValueKind.False)
                    store.SetStar(user.Email, id, starred.GetBoolean());
                if (body.TryGetValue("folder", out var folder) && folder.ValueKind == JsonValueKind.String)
                    store.MoveMessage(user.Email, id, folder.GetString() ?? "inbox");
                var updated = store.GetMessage(user.Email, id)!;
                await Reply(response, new { message = Summary(updated) });
                return;
            }
            case "DELETE":
            {
                var permanent = string.Equals(request.QueryString["permanent"], "true", StringComparison.OrdinalIgnoreCase);
                store.DeleteMessage(user.Email, id, permanent);
                await Reply(response, new { ok = true, permanent });
                return;
            }
            default:
                await Reply(response, new { error = "不支持的请求方法" }, 405);
                return;
        }
    }

    private static object Detail(MailMessage message, bool markedRead) => new
    {
        message.Id,
        message.Folder,
        message.From,
        message.To,
        message.Cc,
        message.Subject,
        message.Text,
        message.Html,
        message.MessageId,
        message.InReplyTo,
        message.References,
        message.Date,
        message.ReceivedAt,
        unread = markedRead ? false : message.Unread,
        message.Starred,
        message.DeliveryStatus,
        message.LastError,
        message.Size,
        message.DkimSigned,
        attachments = message.Attachments.Select((a, index) => new
        {
            index,
            a.FileName,
            a.ContentType,
            a.Size,
            a.Inline,
            url = $"/api/messages/{message.Id}/attachments/{index}",
        }),
        rawUrl = $"/api/messages/{message.Id}/raw",
    };

    private static string Sanitize(string name)
    {
        var cleaned = new string((name ?? "message").Where(c => !Path.GetInvalidFileNameChars().Contains(c)).ToArray()).Trim();
        return cleaned.Length == 0 ? "message" : cleaned;
    }

    // ---------------------------------------------------------------- 发信

    private async Task SendAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var body = await ReadJsonAsync<SendRequest>(request);
        if (body is null) { await Reply(response, new { error = "请求体不是合法 JSON" }, 400); return; }

        var recipients = Mime.Addresses(body.To ?? "");
        var cc = Mime.Addresses(body.Cc ?? "");
        if (recipients.Length == 0) { await Reply(response, new { error = "收件人不能为空" }, 400); return; }
        if (string.IsNullOrWhiteSpace(body.Text) && string.IsNullOrWhiteSpace(body.Html))
        {
            await Reply(response, new { error = "正文不能为空" }, 400);
            return;
        }

        var subject = string.IsNullOrWhiteSpace(body.Subject) ? "(无主题)" : body.Subject!;
        var stored = new List<Attachment>();
        var outgoing = new List<OutgoingAttachment>();
        foreach (var attachment in body.Attachments ?? [])
        {
            if (string.IsNullOrWhiteSpace(attachment.Base64)) continue;
            byte[] data;
            try { data = Convert.FromBase64String(attachment.Base64); }
            catch { await Reply(response, new { error = $"附件 {attachment.FileName} 不是合法 base64" }, 400); return; }

            var contentType = string.IsNullOrWhiteSpace(attachment.ContentType) ? "application/octet-stream" : attachment.ContentType!;
            var fileName = string.IsNullOrWhiteSpace(attachment.FileName) ? "attachment.bin" : attachment.FileName!;
            stored.Add(new Attachment
            {
                FileName = fileName,
                ContentType = contentType,
                Size = data.Length,
                StoredAs = store.SaveAttachment(data, fileName),
            });
            outgoing.Add(new OutgoingAttachment(fileName, contentType, data));
        }

        var raw = Mime.Build(new ComposeRequest(
            user.Email,
            user.DisplayName,
            recipients,
            cc,
            subject,
            body.Text ?? "",
            body.Html,
            outgoing,
            MessageId: null,
            InReplyTo: body.InReplyTo ?? "",
            References: body.InReplyTo ?? ""), config);

        var message = store.QueueOutbound(user.Email, recipients, subject, body.Text ?? "", raw,
            string.Join(", ", cc), body.Html ?? "", body.InReplyTo ?? "", stored);

        AppLog.Info($"[接口] 已入队发信：{user.Email} → {string.Join(", ", recipients)}，主题：{subject}");
        await Reply(response, new { queued = true, messageId = message.Id, recipients, cc }, 202);
    }

    private async Task SaveDraftAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var body = await ReadJsonAsync<DraftRequest>(request) ?? new DraftRequest("", "", "");
        var message = new MailMessage
        {
            OwnerEmail = user.Email,
            Folder = "drafts",
            From = user.Email,
            To = body.To ?? "",
            Subject = string.IsNullOrWhiteSpace(body.Subject) ? "(无主题)" : body.Subject!,
            Text = body.Text ?? "",
            Unread = false,
            DeliveryStatus = "draft",
        };
        store.SaveMessage(message);
        await Reply(response, new { message = Summary(message) }, 201);
    }

    // ---------------------------------------------------------------- 长轮询

    private async Task WatchAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var since = long.TryParse(request.QueryString["since"], out var parsed) ? parsed : store.Version;
        var deadline = DateTimeOffset.UtcNow.AddSeconds(Math.Clamp(config.Api.LongPollSeconds, 1, 120));
        var stats = store.Stats(user.Email);

        while (DateTimeOffset.UtcNow < deadline && store.Version == since)
        {
            await Task.Delay(500);
        }

        await Reply(response, new
        {
            version = store.Version,
            changed = store.Version != since,
            stats = store.Stats(user.Email),
        });
    }

    // ---------------------------------------------------------------- 账号与管理员

    private async Task ChangePasswordAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var body = await ReadJsonAsync<Dictionary<string, string>>(request) ?? [];
        var check = accounts.CheckPassword(body.GetValueOrDefault("password"), user.Email);
        if (!check.Ok)
        {
            await Reply(response, new { error = check.Error }, 400);
            return;
        }
        var password = body["password"];
        if (body.TryGetValue("currentPassword", out var current) && store.Authenticate(user.Email, current) is null)
        {
            await Reply(response, new { error = "当前密码不正确" }, 403);
            return;
        }
        store.ChangePassword(user.Email, password);
        // 改密后把其他设备踢下线（当前这个 token 保留，避免自己也被踢）
        var revoked = store.RemoveSessions(user.Email, ExtractToken(request));
        accounts.Record(user.Email, ClientIp(request), "password-changed", true, $"sessions revoked={revoked}", UserAgent(request));
        AppLog.Info($"[接口] {user.Email} 已修改密码，吊销其他会话 {revoked} 个。");
        await Reply(response, new { ok = true, revokedSessions = revoked });
    }

    private async Task UpdateProfileAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var body = await ReadJsonAsync<ProfileRequest>(request);
        if (body is null || body.DisplayName is null)
        {
            await Reply(response, new { error = "没有可更新的字段（目前支持 displayName）" }, 400);
            return;
        }
        var name = body.DisplayName.Trim();
        if (name.Length > 64) { await Reply(response, new { error = "显示名最多 64 个字符" }, 400); return; }
        accounts.UpdateProfile(user.Email, name);
        accounts.Record(user.Email, ClientIp(request), "profile-updated", true, name, UserAgent(request));
        var fresh = store.FindUser(user.Email);
        await Reply(response, new { ok = true, user = Project(fresh ?? user) });
    }

    private async Task RevokeSessionsAsync(HttpListenerRequest request, HttpListenerResponse response, MailUser user, string? currentToken)
    {
        var body = await ReadJsonAsync<Dictionary<string, JsonElement>>(request) ?? [];
        var all = body.TryGetValue("all", out var a) && a.ValueKind is JsonValueKind.True;
        if (all)
        {
            var removed = accounts.RevokeSessions(user.Email, null);
            accounts.Record(user.Email, ClientIp(request), "session-revoked", true, $"all={removed}", UserAgent(request));
            await Reply(response, new { ok = true, revoked = removed, selfRevoked = true });
            return;
        }
        if (body.TryGetValue("token", out var t) && t.ValueKind == JsonValueKind.String)
        {
            var target = t.GetString() ?? "";
            if (string.IsNullOrWhiteSpace(target)) { await Reply(response, new { error = "token 不能为空" }, 400); return; }
            if (target == currentToken)
            {
                // 允许「把我自己这个会话也吊销」= 等价于登出
                store.RemoveSession(target);
                await Reply(response, new { ok = true, revoked = 1, selfRevoked = true });
                return;
            }
            // 只允许吊销属于该账号的会话，避免越权
            var mine = store.ListSessions(user.Email).Any(s => s.Token == target);
            if (!mine) { await Reply(response, new { error = "该会话不属于当前账号" }, 403); return; }
            store.RemoveSession(target);
            accounts.Record(user.Email, ClientIp(request), "session-revoked", true, "one", UserAgent(request));
            await Reply(response, new { ok = true, revoked = 1, selfRevoked = false });
            return;
        }
        // 默认行为：退出其他设备（保留当前）
        var count = accounts.RevokeSessions(user.Email, currentToken);
        accounts.Record(user.Email, ClientIp(request), "session-revoked", true, $"others={count}", UserAgent(request));
        await Reply(response, new { ok = true, revoked = count, selfRevoked = false });
    }

    private static object ProjectAudit(AuthEvent e) => new
    {
        e.Id, e.Email, e.Ip, e.Reason, e.Success, e.Detail, e.UserAgent, e.At,
    };

    private async Task AdminUsersAsync(HttpListenerRequest request, HttpListenerResponse response, string method)
    {
        if (method == "GET")
        {
            await Reply(response, new
            {
                users = store.ListUsers().Select(x => new { x.Email, x.DisplayName, x.Role, x.Active, x.CreatedAt, x.LastLoginAt }),
            });
            return;
        }
        if (method == "POST")
        {
            var body = await ReadJsonAsync<Dictionary<string, string>>(request) ?? [];
            if (!body.TryGetValue("email", out var email) || !body.TryGetValue("password", out var password) || password.Length < 12)
            {
                await Reply(response, new { error = "需要 email 与至少 12 位 password" }, 400);
                return;
            }
            var created = store.CreateUser(email, password, body.GetValueOrDefault("displayName", "") ?? "");
            await Reply(response, new { user = new { created.Email, created.DisplayName, created.Role, created.Active } }, 201);
            return;
        }
        await Reply(response, new { error = "不支持的请求方法" }, 405);
    }

    private async Task AdminUserPatchAsync(HttpListenerRequest request, HttpListenerResponse response, string email, string method)
    {
        if (method != "PATCH") { await Reply(response, new { error = "不支持的请求方法" }, 405); return; }
        var body = await ReadJsonAsync<Dictionary<string, JsonElement>>(request) ?? [];
        if (body.TryGetValue("active", out var active) && active.ValueKind is JsonValueKind.True or JsonValueKind.False)
        {
            store.SetUserActive(email, active.GetBoolean());
            await Reply(response, new { ok = true, email, active = active.GetBoolean() });
            return;
        }
        if (body.TryGetValue("password", out var password) && password.ValueKind == JsonValueKind.String)
        {
            var value = password.GetString() ?? "";
            if (value.Length < 12) { await Reply(response, new { error = "密码至少需要 12 个字符" }, 400); return; }
            store.ChangePassword(email, value);
            await Reply(response, new { ok = true, email });
            return;
        }
        await Reply(response, new { error = "没有可更新的字段" }, 400);
    }

    // ---------------------------------------------------------------- HTTP 工具

    private static async Task<T?> ReadJsonAsync<T>(HttpListenerRequest request)
    {
        if (!request.HasEntityBody) return default;
        using var reader = new StreamReader(request.InputStream, Encoding.UTF8);
        var text = await reader.ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(text)) return default;
        try { return JsonSerializer.Deserialize<T>(text, new JsonSerializerOptions(JsonSerializerDefaults.Web)); }
        catch (JsonException) { return default; }
    }

    private Task Reply(HttpListenerResponse response, object value, int status = 200)
    {
        var bytes = JsonSerializer.SerializeToUtf8Bytes(value, json);
        response.StatusCode = status;
        response.ContentType = "application/json; charset=utf-8";
        response.ContentLength64 = bytes.Length;
        return WriteAndCloseAsync(response, bytes);
    }

    private static async Task ReplyBinary(HttpListenerResponse response, byte[] data, string contentType, string fileName)
    {
        response.StatusCode = 200;
        response.ContentType = contentType;
        response.ContentLength64 = data.Length;
        response.Headers["Content-Disposition"] = $"attachment; filename*=UTF-8''{Uri.EscapeDataString(fileName)}";
        await WriteAndCloseAsync(response, data);
    }

    private static async Task WriteAndCloseAsync(HttpListenerResponse response, byte[] data)
    {
        try
        {
            await response.OutputStream.WriteAsync(data);
            response.OutputStream.Flush();
        }
        catch (Exception) { /* 客户端提前断开 */ }
        finally { response.Close(); }
    }
}

/// <summary>版本信息（客户端可据此判断兼容性）。</summary>
public static class BuildInfo
{
    /// <summary>
    /// 2.0.1：修正 DKIM 签名输入顺序（RFC 6376 §3.7）。2.0.0 把 DKIM-Signature 头放在
    /// 签名输入的最前面并多带一个结尾 CRLF，导致所有合规验证器（Gmail/Outlook/port25）判 dkim=fail。
    ///
    /// 2.2.0：账号体系（自助注册 / 登录加固 / 邮箱验证码 / 找回密码 / 会话与资料管理 / 认证审计）。
    ///        两条关键设计见 README 第 6.2.2 节：本机托管的邮箱注册免验证（否则验证码邮件投不进
    ///        还没开通的信箱，死循环）；未激活账号先建信箱行、密码只存在验证码记录里。
    /// 2.2.1：入站 SPF/DKIM/DMARC 校验 + 垃圾判定（默认标注并把失败件投垃圾箱，不拒收）；
    ///        新增 --verify-inbound 维护命令；顺带修掉签名端用 ASCII 取签名输入字节的潜在缺陷。
    /// </summary>
    public const string Version = "2.2.1";
    public const string Product = "wpyw.mail.native";
}
