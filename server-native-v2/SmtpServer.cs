using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// SMTP 服务端：
///   25 端口 —— 公网收信（只接受本地收件人，不中继）
///   587 端口 —— 已认证的客户端发信
///
/// 相比 v1 的关键修正：
///  1. DATA 阶段按字节读取（v1 用 StreamReader 读文本再拼回，破坏 8bit 内容与行尾）；
///  2. 只要加载到证书就广告 STARTTLS（v1 只在「非自签名」时才广告，而 AUTH 又要求
///     加密，导致 587 端口完全无法认证的死锁）；
///  3. 收信时补 Received 头，并对认证失败做临时封禁。
/// </summary>
public sealed class SmtpServer
{
    private static readonly ConcurrentDictionary<string, Failure> Failures = new();

    private readonly AppConfig config;
    private readonly IMailStore store;
    private readonly X509Certificate2? certificate;
    private readonly bool advertiseStartTls;

    public SmtpServer(AppConfig config, IMailStore store)
    {
        this.config = config;
        this.store = store;

        if (!string.IsNullOrWhiteSpace(config.TlsCertificatePath) && File.Exists(config.TlsCertificatePath))
        {
            certificate = new X509Certificate2(config.TlsCertificatePath, config.TlsCertificatePassword);
            var selfSigned = certificate.Subject.Equals(certificate.Issuer, StringComparison.OrdinalIgnoreCase);
            advertiseStartTls = config.Smtp.AdvertiseStartTls;
            AppLog.Info($"[SMTP] 已加载 TLS 证书：{certificate.Subject}（{(selfSigned ? "自签名" : "受信任")}，至 {certificate.NotAfter:yyyy-MM-dd}）");
            if (selfSigned) AppLog.Warn("[SMTP] 证书是自签名：STARTTLS 会正常广告，但部分严格客户端会拒绝，建议换取受信任证书。");
        }
        else
        {
            AppLog.Warn("[SMTP] 未找到 TLS 证书；STARTTLS 不可用，587 端口将无法完成认证（AUTH 要求加密）。");
            AppLog.Warn("[SMTP] 请配置 TlsCertificatePath 指向 mail.<你的域名> 的 PFX 证书。");
        }
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var inbound = new TcpListener(IPAddress.Any, config.SmtpPort);
        var submission = new TcpListener(IPAddress.Any, config.SubmissionPort);
        inbound.Start();
        submission.Start();
        AppLog.Info($"[SMTP] 收信端口已监听：{config.SmtpPort}");
        AppLog.Info($"[SMTP] 客户端发信端口已监听：{config.SubmissionPort}（需 STARTTLS + AUTH）");
        await Task.WhenAll(AcceptLoop(inbound, false, cancellationToken), AcceptLoop(submission, true, cancellationToken));
    }

    private async Task AcceptLoop(TcpListener listener, bool submission, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(token);
                _ = Task.Run(() => SafeHandleAsync(client, submission, token));
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { AppLog.Error($"[SMTP] {(submission ? 587 : 25)} 接收循环异常：{ex.Message}"); }
        finally { listener.Stop(); }
    }

    private async Task SafeHandleAsync(TcpClient client, bool submission, CancellationToken token)
    {
        try { await HandleClient(client, submission, token); }
        catch (Exception ex) { AppLog.Error($"[SMTP] 会话处理异常：{ex.Message}"); }
        finally { client.Dispose(); }
    }

    private async Task HandleClient(TcpClient client, bool submission, CancellationToken token)
    {
        var rawStream = client.GetStream();
        Stream stream = rawStream;
        var reader = new SmtpReader(stream);
        var writer = NewWriter(stream);
        var tls = false;
        string? authenticatedUser = null;
        string? sender = null;
        var recipients = new List<string>();

        var remoteIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "未知地址";
        var remote = client.Client.RemoteEndPoint?.ToString() ?? remoteIp;
        var clientHelo = "";

        try
        {
            if (IsBanned(remoteIp))
            {
                AppLog.Warn($"[SMTP] {remoteIp} 已被临时封禁，直接断开。");
                await Send(writer, "421 Too many authentication failures, try again later");
                return;
            }

            AppLog.Info($"[SMTP] 收到连接：{remote}，模式={(submission ? "客户端发信" : "公网收信")}");
            var banner = submission ? $"220 {config.Hostname} ESMTP WpywMail submission" : $"220 {config.Hostname} ESMTP WpywMail";
            await Send(writer, banner);

            while (!token.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(token);
                if (line is null) break;
                var upper = line.Trim().ToUpperInvariant();

                if (upper.StartsWith("EHLO") || upper.StartsWith("HELO"))
                {
                    clientHelo = line[(line.IndexOf(' ') + 1)..].Trim();
                    await SendCapabilities(writer, submission, tls);
                }
                else if (upper == "STARTTLS")
                {
                    if (certificate is null || !advertiseStartTls)
                    {
                        await Send(writer, "454 TLS not available");
                        continue;
                    }
                    await Send(writer, "220 Ready to start TLS");
                    var ssl = new SslStream(stream, leaveInnerStreamOpen: false);
                    await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                    {
                        ServerCertificate = certificate,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                        ClientCertificateRequired = false,
                    }, token);
                    stream = ssl;
                    reader = new SmtpReader(stream);
                    writer = NewWriter(stream);
                    tls = true;
                    authenticatedUser = null;
                    AppLog.Info($"[SMTP] {remote} 已建立 TLS 会话。");
                }
                else if (upper.StartsWith("AUTH"))
                {
                    var allowed = submission || config.Smtp.AllowAuthOnInbound;
                    if (!allowed || !tls)
                    {
                        // 关键修复：明确告诉客户端为什么不能认证，而不是让它无解
                        await Send(writer, "538 Encryption required for authentication");
                        continue;
                    }
                    var result = await AuthenticateAsync(line, reader, writer, token);
                    if (result is null)
                    {
                        RegisterFailure(remoteIp);
                        AppLog.Warn($"[SMTP] {remote} 认证失败。");
                        await Send(writer, "535 Authentication failed");
                    }
                    else
                    {
                        ClearFailures(remoteIp);
                        authenticatedUser = result;
                        AppLog.Info($"[SMTP] {remote} 认证成功：{result}");
                        await Send(writer, "235 Authentication successful");
                    }
                }
                else if (upper == "RSET")
                {
                    sender = null;
                    recipients.Clear();
                    await Send(writer, "250 Reset");
                }
                else if (upper.StartsWith("NOOP"))
                {
                    await Send(writer, "250 OK");
                }
                else if (upper.StartsWith("MAIL FROM:"))
                {
                    // ── 安全修复（2026-09-15）───────────────────────────────────
                    // 原实现在这里「先赋值 sender，再做认证校验」，导致 MAIL FROM
                    // 被 530 拒绝之后 sender 依然非空，于是 RCPT 与 DATA 两处守卫
                    // （sender is null）全部失效：未认证客户端可以走完 RCPT + DATA
                    // 全流程，报文会被 SaveRaw 写进 blob 存储。开放中继之所以没有
                    // 真正打通，只是因为随后对 null 账号解引用抛了异常 —— 属偶然，
                    // 不是设计。现在改为通过全部校验后才赋值。
                    var candidate = Mime.Addresses(line).FirstOrDefault() ?? ExtractAddress(line);
                    sender = null;
                    recipients.Clear();
                    if (submission && authenticatedUser is null)
                    {
                        AppLog.Warn($"[SMTP] {remote} 未认证就尝试发信：{candidate}（已拒绝）");
                        await Send(writer, "530 Authentication required");
                    }
                    else if (submission && config.Smtp.EnforceSenderMatch &&
                             !string.Equals(candidate, authenticatedUser, StringComparison.OrdinalIgnoreCase))
                    {
                        AppLog.Warn($"[SMTP] {remote} 发件人 {candidate} 与已认证账号 {authenticatedUser} 不匹配。");
                        await Send(writer, "553 Sender must match authenticated mailbox");
                    }
                    else
                    {
                        sender = candidate;
                        AppLog.Info($"[SMTP] {remote} MAIL FROM：{sender}");
                        await Send(writer, "250 2.1.0 Sender accepted");
                    }
                }
                else if (upper.StartsWith("RCPT TO:"))
                {
                    var recipient = Mime.Addresses(line).FirstOrDefault() ?? ExtractAddress(line);
                    if (sender is null)
                    {
                        await Send(writer, "503 5.5.1 Need MAIL FROM first");
                    }
                    else if (submission && authenticatedUser is null)
                    {
                        // 安全修复（2026-09-15）：提交端口必须已认证才允许指定收件人。
                        // 原实现只在 MAIL FROM 处拦未认证，收件人完全不校验，且中继
                        // 检查写成 !submission，于是 587 上外域地址也会被 250 接受。
                        AppLog.Warn($"[SMTP] {remote} 未认证的提交会话尝试指定收件人：{recipient}（已拒绝）");
                        await Send(writer, "530 Authentication required");
                    }
                    else if (!submission && !store.IsLocalAddress(recipient))
                    {
                        AppLog.Warn($"[SMTP] {remote} 非本地收件人被拒绝：{recipient}");
                        await Send(writer, "550 5.7.1 Relay denied");
                    }
                    else
                    {
                        recipients.Add(recipient);
                        AppLog.Info($"[SMTP] {remote} RCPT TO：{recipient}");
                        await Send(writer, "250 2.1.5 Recipient accepted");
                    }
                }
                else if (upper == "DATA")
                {
                    if (sender is null || recipients.Count == 0)
                    {
                        await Send(writer, "503 5.5.1 Need sender and recipient");
                        continue;
                    }
                    if (submission && authenticatedUser is null)
                    {
                        // 安全修复（2026-09-15）：双保险。即使前面的状态机被绕过，
                        // 也绝不让未认证会话进入数据阶段 —— 否则读取到的报文会先被
                        // SaveRaw 落盘，形成未认证、无限速、可并发的写盘路径。
                        AppLog.Error($"[SMTP] {remote} 未认证的提交会话尝试 DATA，已拒绝。");
                        await Send(writer, "530 Authentication required");
                        sender = null;
                        recipients.Clear();
                        continue;
                    }
                    await Send(writer, "354 End data with <CRLF>.<CRLF>");
                    byte[] raw;
                    try
                    {
                        raw = await reader.ReadDataAsync(config.Smtp.MaxMessageBytes, token);
                    }
                    catch (InvalidOperationException ex)
                    {
                        await Send(writer, $"552 5.3.4 {ex.Message}");
                        sender = null;
                        recipients.Clear();
                        continue;
                    }

                    await StoreIncomingAsync(raw, submission, sender, recipients, authenticatedUser, remoteIp, remote, clientHelo, token);
                    await Send(writer, "250 2.0.0 Message accepted");
                    sender = null;
                    recipients.Clear();
                }
                else if (upper == "QUIT")
                {
                    await Send(writer, "221 Bye");
                    break;
                }
                else
                {
                    await Send(writer, "502 5.5.2 Command not implemented");
                }
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException or ObjectDisposedException) { }
        catch (Exception ex) { AppLog.Error($"[SMTP] {remote} 会话错误：{ex.Message}"); }
        finally
        {
            rawStream.Dispose();
        }
    }

    /// <summary>把收到的报文落库；submission 模式则进入发件队列。</summary>
    private async Task StoreIncomingAsync(byte[] raw, bool submission, string sender, List<string> recipients,
        string? authenticatedUser, string remoteIp, string remote, string helo, CancellationToken token)
    {
        if (config.Smtp.AddReceivedHeader && !submission)
        {
            raw = AddReceivedHeader(raw, remoteIp, recipients);
        }

        if (submission)
        {
            if (string.IsNullOrEmpty(authenticatedUser))
            {
                // 安全修复（2026-09-15）：提交模式必须有已认证账号。
                // 原实现直接使用 authenticatedUser!（null 宽容运算符），在未认证
                // 路径下传入 null，最终在 SqliteStore.InsertMessageLocked 里对
                // OwnerEmail 解引用抛 NullReferenceException —— 落盘已经发生，
                // 异常只是恰好阻止了入队。
                AppLog.Error($"[SMTP] 拒绝入队：提交会话没有已认证账号（发件人 {sender}）。");
                return;
            }
            var queued = Mime.Parse(raw);
            // 客户端提交的报文按原样排队（DKIM 在投递时签名），但正文/主题仍解析入库便于列表展示
            store.QueueOutbound(authenticatedUser!, recipients.ToArray(),
                queued.Subject, queued.Text, raw, queued.Cc, queued.Html, queued.InReplyTo);
            AppLog.Info($"[SMTP] 已进入发件队列：{authenticatedUser} → {string.Join(", ", recipients)}，主题：{queued.Subject}");
            return;
        }

        // ── 入站身份校验：SPF / DKIM / DMARC（默认只标注 + 投垃圾箱，不拒收）
        InboundAuthVerdict? verdict = null;
        if (config.InboundAuth.Enabled)
        {
            try
            {
                verdict = await InboundAuth.CheckAsync(raw, remoteIp, helo, sender, config, token);
                raw = InboundAuth.PrependHeaders(raw, verdict.HeaderBlock);
                AppLog.Info($"[入站校验] {sender} → {string.Join(", ", recipients)}：spf={verdict.Spf}({verdict.SpfDomain}) "
                    + $"dkim={verdict.Dkim} dmarc={verdict.Dmarc}(p={verdict.DmarcPolicy}) 分数={verdict.Score}"
                    + (verdict.Spam ? " → 投垃圾箱" : ""));
                foreach (var reason in verdict.Reasons) AppLog.Warn($"[入站校验] {sender}：{reason}");
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                // 校验自身失败不能影响收信：宁可放过也不丢信
                AppLog.Error($"[入站校验] 出错（按未判定处理）：{ex.Message}");
            }
        }

        var parsed = Mime.Parse(raw);
        var folder = verdict is { Spam: true } ? "spam" : "inbox";

        foreach (var recipient in recipients.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            if (store.FindUser(recipient) is null) continue;

            var attachments = new List<Attachment>();
            foreach (var attachment in parsed.Attachments)
            {
                if (attachment.Data.Length == 0) continue;
                attachments.Add(new Attachment
                {
                    FileName = attachment.FileName,
                    ContentType = attachment.ContentType,
                    Size = attachment.Data.Length,
                    StoredAs = store.SaveAttachment(attachment.Data, attachment.FileName),
                    ContentId = attachment.ContentId,
                    Inline = attachment.Inline,
                });
            }

            store.SaveMessage(new MailMessage
            {
                OwnerEmail = recipient.ToLowerInvariant(),
                Folder = folder,
                From = parsed.From.Length > 0 ? parsed.From : sender,
                To = recipient,
                Cc = parsed.Cc,
                Subject = parsed.Subject,
                Text = parsed.Text,
                Html = parsed.Html,
                MessageId = parsed.MessageId,
                InReplyTo = parsed.InReplyTo,
                References = parsed.References,
                Date = parsed.Date ?? DateTimeOffset.UtcNow,
                ReceivedAt = DateTimeOffset.UtcNow,
                DeliveryStatus = verdict is { Spam: true } ? "received-spam" : "received",
                Unread = true,
                Attachments = attachments,
            }, raw);
        }

        AppLog.Info($"[SMTP] 已接收邮件：{sender} → {string.Join(", ", recipients)}，主题：{parsed.Subject}"
            + $"（{(folder == "spam" ? "垃圾箱" : "收件箱")}{parsed.Attachments.Count switch { > 0 => $"，附件 {parsed.Attachments.Count} 个", _ => "" }}）");
    }

    private byte[] AddReceivedHeader(byte[] raw, string remoteIp, List<string> recipients)
    {
        var header = $"Received: from {remoteIp} by {config.Hostname} with ESMTP id {Guid.NewGuid():N} " +
                     $"for <{recipients.FirstOrDefault()}>; {Mime.FormatDate(DateTimeOffset.Now)}{"\r\n"}";
        var output = new MemoryStream(raw.Length + header.Length + 16);
        output.Write(Encoding.ASCII.GetBytes(header));
        output.Write(raw);
        return output.ToArray();
    }

    private async Task SendCapabilities(StreamWriter writer, bool submission, bool tls)
    {
        var capabilities = new List<string>
        {
            $"SIZE {config.Smtp.MaxMessageBytes}",
            "8BITMIME",
            "PIPELINING",
            "ENHANCEDSTATUSCODES",
        };
        if (certificate is not null && advertiseStartTls && !tls) capabilities.Add("STARTTLS");
        if (tls && (submission || config.Smtp.AllowAuthOnInbound)) capabilities.Add("AUTH PLAIN LOGIN");

        await Send(writer, $"250-{config.Hostname}");
        for (var i = 0; i < capabilities.Count; i++)
        {
            var prefix = i == capabilities.Count - 1 ? "250 " : "250-";
            await Send(writer, prefix + capabilities[i]);
        }
    }

    private async Task<string?> AuthenticateAsync(string command, SmtpReader reader, StreamWriter writer, CancellationToken token)
    {
        var parts = command.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        string? email = null;
        string? password = null;

        if (parts.Length >= 2 && parts[1].Equals("PLAIN", StringComparison.OrdinalIgnoreCase))
        {
            var payload = parts.Length >= 3 ? parts[2] : null;
            if (string.IsNullOrEmpty(payload))
            {
                await Send(writer, "334 ");
                payload = (await reader.ReadLineAsync(token) ?? "").Trim();
            }
            var bytes = TryBase64(payload);
            if (bytes is null) return null;
            var values = Encoding.UTF8.GetString(bytes).Split('\0');
            email = values.Length > 1 ? values[1] : null;
            password = values.Length > 2 ? values[2] : null;
        }
        else if (parts.Length >= 2 && parts[1].Equals("LOGIN", StringComparison.OrdinalIgnoreCase))
        {
            string? userPayload = parts.Length >= 3 ? parts[2] : null;
            if (string.IsNullOrEmpty(userPayload))
            {
                await Send(writer, "334 VXNlcm5hbWU6");
                userPayload = (await reader.ReadLineAsync(token) ?? "").Trim();
            }
            await Send(writer, "334 UGFzc3dvcmQ6");
            var passwordPayload = (await reader.ReadLineAsync(token) ?? "").Trim();

            var userBytes = TryBase64(userPayload);
            var passwordBytes = TryBase64(passwordPayload);
            if (userBytes is null || passwordBytes is null) return null;
            email = Encoding.UTF8.GetString(userBytes);
            password = Encoding.UTF8.GetString(passwordBytes);
        }
        else
        {
            await Send(writer, "504 5.5.4 Authentication mechanism not supported");
            return null;
        }

        return store.Authenticate(email ?? "", password ?? "")?.Email;
    }

    private static byte[]? TryBase64(string value)
    {
        try { return Convert.FromBase64String(value.Trim()); }
        catch { return null; }
    }

    // ---------------------------------------------------------------- 认证失败封禁

    private sealed record Failure(int Count, DateTimeOffset Until);

    private static bool IsBanned(string ip)
    {
        if (!Failures.TryGetValue(ip, out var failure)) return false;
        if (failure.Until > DateTimeOffset.UtcNow) return true;
        Failures.TryRemove(ip, out _);
        return false;
    }

    private void RegisterFailure(string ip)
    {
        var threshold = Math.Max(1, config.Smtp.AuthFailuresBeforeBan);
        var ban = TimeSpan.FromMinutes(Math.Max(1, config.Smtp.BanMinutes));
        Failures.AddOrUpdate(ip,
            _ => new Failure(1, DateTimeOffset.MinValue),
            (_, existing) => new Failure(existing.Count + 1, existing.Count + 1 >= threshold ? DateTimeOffset.UtcNow.Add(ban) : existing.Until));

        if (Failures.TryGetValue(ip, out var current) && current.Count >= threshold)
            AppLog.Warn($"[SMTP] {ip} 认证失败 {current.Count} 次，已临时封禁 {ban.TotalMinutes:0} 分钟。");
    }

    private static void ClearFailures(string ip) => Failures.TryRemove(ip, out _);

    // ---------------------------------------------------------------- 工具

    private static string ExtractAddress(string command)
    {
        var start = command.IndexOf('<');
        var end = command.IndexOf('>', start + 1);
        return start >= 0 && end > start
            ? command[(start + 1)..end].Trim().ToLowerInvariant()
            : command[(command.IndexOf(':') + 1)..].Trim().ToLowerInvariant();
    }

    // 控制通道只传 ASCII 命令；DATA 走 SmtpReader 的字节通道
    private static StreamWriter NewWriter(Stream stream) => new(stream, Encoding.ASCII, 8192, true) { AutoFlush = true, NewLine = "\r\n" };
    private static Task Send(StreamWriter writer, string value) => writer.WriteLineAsync(value);
}
