using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;

namespace WpywMail.Native;

public sealed class ApiServer
{
    private readonly AppConfig config;
    private readonly FileStore store;
    private readonly HttpListener listener = new();
    private readonly ConcurrentDictionary<string, Session> sessions = new();
    private readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web);

    public ApiServer(AppConfig config, FileStore store) { this.config = config; this.store = store; listener.Prefixes.Add(config.HttpPrefix); }

    public async Task RunAsync(CancellationToken token)
    {
        listener.Start();
        AppLog.Info($"[接口] 已监听：{config.HttpPrefix}");
        try
        {
            while (!token.IsCancellationRequested)
            {
                var context = await listener.GetContextAsync().WaitAsync(token);
                _ = Task.Run(() => Handle(context), token);
            }
        }
        catch (OperationCanceledException) { }
        finally { listener.Stop(); }
    }

    private async Task Handle(HttpListenerContext context)
    {
        var request = context.Request; var response = context.Response;
        response.Headers["Access-Control-Allow-Origin"] = "*";
        response.Headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
        response.Headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, OPTIONS";
        if (request.HttpMethod == "OPTIONS") { response.StatusCode = 204; response.Close(); return; }
        try
        {
            var path = request.Url?.AbsolutePath.TrimEnd('/') ?? "";
            if (path == "/api/health") { await Reply(response, new { ok = true, service = "wpyw.mail.native", hostname = config.Hostname, domain = config.Domain }); return; }
            if (path == "/api/login" && request.HttpMethod == "POST") { await Login(request, response); return; }
            var user = Authenticate(request);
            if (user is null) { await Reply(response, new { error = "登录已失效" }, 401); return; }
            if (path == "/api/me") { await Reply(response, new { user = new { email = user.Email, role = user.Role }, stats = store.Stats(user.Email) }); return; }
            if (path == "/api/config") { await Reply(response, new { domain = config.Domain, hostname = config.Hostname, account = user.Email, protocols = new { smtp = config.SmtpPort, submission = config.SubmissionPort, api = config.HttpPrefix } }); return; }
            if (path == "/api/logout" && request.HttpMethod == "POST") { RemoveSession(request); await Reply(response, new { ok = true }); return; }
            if (path == "/api/messages" && request.HttpMethod == "GET") { await ListMessages(request, response, user); return; }
            if (path.StartsWith("/api/messages/", StringComparison.OrdinalIgnoreCase)) { await MessageDetail(request, response, user, path[14..]); return; }
            if (path == "/api/send" && request.HttpMethod == "POST") { await SendMessage(request, response, user); return; }
            if (path == "/api/account/password" && request.HttpMethod == "POST") { await ChangePassword(request, response, user); return; }
            if (path == "/api/admin/users" && user.Role == "admin") { await AdminUsers(request, response); return; }
            await Reply(response, new { error = "接口不存在" }, 404);
        }
        catch (Exception ex) { AppLog.Error($"[接口] {request.HttpMethod} {request.Url}：{ex.Message}"); await Reply(response, new { error = ex.Message }, 500); }
    }

    private async Task Login(HttpListenerRequest request, HttpListenerResponse response)
    {
        var body = await ReadJson<LoginRequest>(request) ?? new LoginRequest("", "");
        var user = store.Authenticate(body.Email, body.Password);
        if (user is null) { await Reply(response, new { error = "邮箱或密码不正确" }, 401); return; }
        var token = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(32)).ToLowerInvariant();
        sessions[token] = new Session(user.Email, DateTimeOffset.UtcNow.AddDays(7));
        await Reply(response, new { token, user = new { email = user.Email, role = user.Role, domain = config.Domain } });
    }

    private MailUser? Authenticate(HttpListenerRequest request)
    {
        var token = request.Headers["Authorization"]?.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase).Trim();
        if (string.IsNullOrWhiteSpace(token) || !sessions.TryGetValue(token, out var session) || session.Expires < DateTimeOffset.UtcNow) return null;
        return store.FindUser(session.Email);
    }

    private void RemoveSession(HttpListenerRequest request)
    {
        var token = request.Headers["Authorization"]?.Replace("Bearer ", "", StringComparison.OrdinalIgnoreCase).Trim();
        if (!string.IsNullOrWhiteSpace(token)) sessions.TryRemove(token, out _);
    }

    private async Task ListMessages(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var folder = request.QueryString["folder"] ?? "inbox"; var query = request.QueryString["q"] ?? "";
        var result = store.ListMessages(user.Email, folder, query).Select(x => new { x.Id, x.From, x.To, x.Subject, x.Date, x.Unread, x.Starred, x.DeliveryStatus, preview = x.Text.Replace("\r", " ").Replace("\n", " ")[..Math.Min(140, x.Text.Length)] });
        await Reply(response, new { messages = result });
    }

    private async Task MessageDetail(HttpListenerRequest request, HttpListenerResponse response, MailUser user, string id)
    {
        var message = store.GetMessage(user.Email, id);
        if (message is null) { await Reply(response, new { error = "邮件不存在" }, 404); return; }
        store.MarkRead(user.Email, id);
        await Reply(response, new { message });
    }

    private async Task SendMessage(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var body = await ReadJson<SendRequest>(request) ?? new SendRequest("", "", "");
        var recipients = Mime.Addresses(body.To);
        if (recipients.Length == 0 || string.IsNullOrWhiteSpace(body.Subject) || string.IsNullOrWhiteSpace(body.Text)) { await Reply(response, new { error = "收件人、主题和正文不能为空" }, 400); return; }
        var raw = Mime.Build(user.Email, recipients, body.Subject, body.Text);
        var message = store.QueueOutbound(user.Email, recipients, body.Subject, body.Text, raw);
        await Reply(response, new { queued = true, messageId = message.Id }, 202);
    }

    private async Task ChangePassword(HttpListenerRequest request, HttpListenerResponse response, MailUser user)
    {
        var body = await ReadJson<Dictionary<string, string>>(request) ?? new();
        if (!body.TryGetValue("password", out var password) || password.Length < 12) { await Reply(response, new { error = "密码至少需要 12 个字符" }, 400); return; }
        store.ChangePassword(user.Email, password); await Reply(response, new { ok = true });
    }

    private async Task AdminUsers(HttpListenerRequest request, HttpListenerResponse response)
    {
        if (request.HttpMethod == "GET") { await Reply(response, new { users = store.ListUsers().Select(x => new { x.Email, x.DisplayName, x.Role, x.Active }) }); return; }
        if (request.HttpMethod == "POST")
        {
            var body = await ReadJson<Dictionary<string, string>>(request) ?? new();
            if (!body.TryGetValue("email", out var email) || !body.TryGetValue("password", out var password) || password.Length < 12) { await Reply(response, new { error = "邮箱和至少 12 位密码是必需的" }, 400); return; }
            var user = store.CreateUser(email, password, body.GetValueOrDefault("displayName", "")); await Reply(response, new { user = new { user.Email, user.DisplayName, user.Role } }, 201); return;
        }
        await Reply(response, new { error = "不支持的请求方法" }, 405);
    }

    private static async Task<T?> ReadJson<T>(HttpListenerRequest request) { using var reader = new StreamReader(request.InputStream, Encoding.UTF8); return JsonSerializer.Deserialize<T>(await reader.ReadToEndAsync(), new JsonSerializerOptions(JsonSerializerDefaults.Web)); }
    private async Task Reply(HttpListenerResponse response, object value, int status = 200) { response.StatusCode = status; response.ContentType = "application/json; charset=utf-8"; var bytes = JsonSerializer.SerializeToUtf8Bytes(value, json); response.ContentLength64 = bytes.Length; await response.OutputStream.WriteAsync(bytes); response.Close(); }
    private sealed record Session(string Email, DateTimeOffset Expires);
}
