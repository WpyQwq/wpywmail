using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WpywMail.Native;

public sealed class SmtpServer
{
    private readonly AppConfig config;
    private readonly FileStore store;
    private readonly X509Certificate2? certificate;
    private readonly bool advertiseStartTls;

    public SmtpServer(AppConfig config, FileStore store)
    {
        this.config = config;
        this.store = store;
        if (File.Exists(config.TlsCertificatePath)) certificate = new X509Certificate2(config.TlsCertificatePath, config.TlsCertificatePassword);
        advertiseStartTls = certificate is not null && !certificate.Subject.Equals(certificate.Issuer, StringComparison.OrdinalIgnoreCase);
        if (certificate is null) AppLog.Warn("[SMTP] 未找到 TLS 证书；正式公开使用前请配置 TlsCertificatePath。");
        else if (!advertiseStartTls) AppLog.Warn("[SMTP] 当前 TLS 证书是自签名证书，公网收信暂不发布 STARTTLS，避免远端因证书不受信而退信。");
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        var inbound = new TcpListener(IPAddress.Any, config.SmtpPort);
        var submission = new TcpListener(IPAddress.Any, config.SubmissionPort);
        inbound.Start(); submission.Start();
        AppLog.Info($"[SMTP] 收信端口已监听：{config.SmtpPort}");
        AppLog.Info($"[SMTP] 客户端发信端口已监听：{config.SubmissionPort}");
        await Task.WhenAll(AcceptLoop(inbound, false, cancellationToken), AcceptLoop(submission, true, cancellationToken));
    }

    private async Task AcceptLoop(TcpListener listener, bool submission, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(token);
                _ = Task.Run(() => HandleClient(client, submission, token), token);
            }
        }
        catch (OperationCanceledException) { }
        finally { listener.Stop(); }
    }

    private async Task HandleClient(TcpClient client, bool submission, CancellationToken token)
    {
        await using var rawStream = client.GetStream();
        Stream stream = rawStream;
        var reader = NewReader(stream);
        var writer = NewWriter(stream);
        var tls = false;
        string? authenticatedUser = null;
        string? sender = null;
        var recipients = new List<string>();
        var remote = client.Client.RemoteEndPoint?.ToString() ?? "未知地址";
        try
        {
            AppLog.Info($"[SMTP] 收到连接：{remote}，模式={(submission ? "客户端发信" : "公网收信")}");
            await Send(writer, $"220 {config.Hostname} ESMTP WpywMail");
            while (!token.IsCancellationRequested)
            {
                var line = await reader.ReadLineAsync(token);
                if (line is null) break;
                var command = line.Trim();
                var upper = command.ToUpperInvariant();
                if (upper.StartsWith("EHLO") || upper.StartsWith("HELO"))
                {
                    await SendMulti(writer, $"250-{config.Hostname}", "250-SIZE 26214400", "250-8BITMIME", "250-PIPELINING", advertiseStartTls && !tls ? "250-STARTTLS" : "250 AUTH LOGIN PLAIN");
                    if (advertiseStartTls && !tls) await Send(writer, "250 AUTH LOGIN PLAIN");
                }
                else if (upper == "STARTTLS")
                {
                    if (certificate is null || (!submission && !advertiseStartTls)) { await Send(writer, "454 TLS unavailable"); continue; }
                    await Send(writer, "220 Ready to start TLS");
                    var ssl = new SslStream(stream, false);
                    await ssl.AuthenticateAsServerAsync(new SslServerAuthenticationOptions { ServerCertificate = certificate, EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13 }, token);
                    stream = ssl; reader = NewReader(stream); writer = NewWriter(stream); tls = true; authenticatedUser = null;
                }
                else if (upper.StartsWith("AUTH"))
                {
                    if (submission && !tls) { await Send(writer, "538 Encryption required for authentication"); continue; }
                    authenticatedUser = await Authenticate(command, reader, writer, token);
                    await Send(writer, authenticatedUser is null ? "535 Authentication failed" : "235 Authentication successful");
                }
                else if (upper == "RSET")
                {
                    sender = null; recipients.Clear(); await Send(writer, "250 Reset");
                }
                else if (upper.StartsWith("MAIL FROM:"))
                {
                    sender = ExtractAddress(command); recipients.Clear();
                    if (submission && authenticatedUser is null) { AppLog.Warn($"[SMTP] {remote} 未认证就尝试发信：{sender}"); await Send(writer, "530 Authentication required"); }
                    else if (submission && !sender.Equals(authenticatedUser, StringComparison.OrdinalIgnoreCase)) { AppLog.Warn($"[SMTP] {remote} 发件人不匹配：{sender}"); await Send(writer, "553 Sender must match authenticated mailbox"); }
                    else { AppLog.Info($"[SMTP] {remote} MAIL FROM：{sender}"); await Send(writer, "250 Sender accepted"); }
                }
                else if (upper.StartsWith("RCPT TO:"))
                {
                    var recipient = ExtractAddress(command);
                    if (sender is null) { AppLog.Warn($"[SMTP] {remote} 未先发送 MAIL FROM 就发送 RCPT TO：{recipient}"); await Send(writer, "503 Need MAIL FROM first"); }
                    else if (!submission && !store.IsLocalAddress(recipient)) { AppLog.Warn($"[SMTP] {remote} 非本地收件人被拒绝：{recipient}"); await Send(writer, "550 Relay denied"); }
                    else { recipients.Add(recipient); AppLog.Info($"[SMTP] {remote} RCPT TO：{recipient}"); await Send(writer, "250 Recipient accepted"); }
                }
                else if (upper == "DATA")
                {
                    if (sender is null || recipients.Count == 0) { await Send(writer, "503 Need sender and recipient"); continue; }
                    await Send(writer, "354 End data with <CRLF>.<CRLF>");
                    var raw = await ReadData(reader, token);
                    var parsed = Mime.Parse(raw);
                    if (submission)
                    {
                        store.QueueOutbound(authenticatedUser!, recipients.ToArray(), parsed.Subject, parsed.Text, raw);
                    }
                    else
                    {
                        foreach (var recipient in recipients.Distinct(StringComparer.OrdinalIgnoreCase))
                        {
                            if (store.FindUser(recipient) is not null)
                                store.SaveMessage(new MailMessage { OwnerEmail = recipient.ToLowerInvariant(), Folder = "inbox", From = parsed.From.Length > 0 ? parsed.From : sender, To = recipient, Subject = parsed.Subject, Text = parsed.Text, MessageId = parsed.MessageId, Date = DateTimeOffset.UtcNow, DeliveryStatus = "received" }, raw);
                        }
                        AppLog.Info($"[SMTP] 已接收邮件：{sender} → {string.Join(", ", recipients)}，主题：{parsed.Subject}");
                    }
                    await Send(writer, "250 Message queued"); sender = null; recipients.Clear();
                }
                else if (upper == "NOOP") await Send(writer, "250 OK");
                else if (upper == "QUIT") { await Send(writer, "221 Bye"); break; }
                else await Send(writer, "502 Command not implemented");
            }
        }
        catch (Exception ex) when (ex is IOException or SocketException or OperationCanceledException) { }
        catch (Exception ex) { AppLog.Error($"[SMTP] {remote} 会话错误：{ex.Message}"); }
        finally { client.Dispose(); }
    }

    private async Task<string?> Authenticate(string command, StreamReader reader, StreamWriter writer, CancellationToken token)
    {
        var parts = command.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        string? email = null; string? password = null;
        if (parts.Length >= 3 && parts[1].Equals("PLAIN", StringComparison.OrdinalIgnoreCase))
        {
            var bytes = Convert.FromBase64String(parts[2]);
            var values = Encoding.UTF8.GetString(bytes).Split('\0');
            email = values.Length > 1 ? values[1] : null; password = values.Length > 2 ? values[2] : null;
        }
        else if (parts.Length >= 2 && parts[1].Equals("LOGIN", StringComparison.OrdinalIgnoreCase))
        {
            await Send(writer, "334 VXNlcm5hbWU6"); email = Encoding.UTF8.GetString(Convert.FromBase64String(await reader.ReadLineAsync(token) ?? ""));
            await Send(writer, "334 UGFzc3dvcmQ6"); password = Encoding.UTF8.GetString(Convert.FromBase64String(await reader.ReadLineAsync(token) ?? ""));
        }
        else { await Send(writer, "504 Authentication mechanism not supported"); return null; }
        return store.Authenticate(email ?? "", password ?? "")?.Email;
    }

    private static async Task<byte[]> ReadData(StreamReader reader, CancellationToken token)
    {
        var lines = new List<string>();
        while (true)
        {
            var line = await reader.ReadLineAsync(token) ?? ".";
            if (line == ".") break;
            lines.Add(line.StartsWith("..") ? line[1..] : line);
            if (lines.Sum(x => x.Length) > 25 * 1024 * 1024) throw new InvalidOperationException("Message too large");
        }
        return Encoding.UTF8.GetBytes(string.Join("\r\n", lines) + "\r\n");
    }

    private static string ExtractAddress(string command)
    {
        var start = command.IndexOf('<'); var end = command.IndexOf('>', start + 1);
        return start >= 0 && end > start ? command[(start + 1)..end].Trim().ToLowerInvariant() : command[(command.IndexOf(':') + 1)..].Trim().ToLowerInvariant();
    }

    private static StreamReader NewReader(Stream stream) => new(stream, Encoding.UTF8, false, 8192, true);
    private static StreamWriter NewWriter(Stream stream) => new(stream, new UTF8Encoding(false), 8192, true) { AutoFlush = true, NewLine = "\r\n" };
    private static Task Send(StreamWriter writer, string value) => writer.WriteLineAsync(value);
    private static async Task SendMulti(StreamWriter writer, params string[] lines) { foreach (var line in lines) await Send(writer, line); }
}
