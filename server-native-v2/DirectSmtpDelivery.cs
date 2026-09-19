using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// 出站投递。支持两种模式：
///   direct —— 查 MX 直接投递（默认）
///   relay  —— 交给上游 SMTP 中继（可带认证与 STARTTLS）
///
/// 相比 v1 的关键修正：
///   DATA 阶段按「字节」写出（v1 用 Encoding.ASCII 的 StreamWriter，导致所有中文变成 '?'），
///   并显式处理 dot-stuffing 与行尾规范化。
/// </summary>
public sealed class DirectSmtpDelivery
{
    private readonly AppConfig config;
    private readonly IMailStore store;

    public DirectSmtpDelivery(AppConfig config, IMailStore store)
    {
        this.config = config;
        this.store = store;
    }

    public async Task DeliverAsync(MailMessage message, string[] recipients, byte[] raw, CancellationToken token)
    {
        if (recipients.Length == 0) throw new InvalidOperationException("没有可投递的收件人。");

        // 本地收件人直接入库，不必绕一圈 SMTP 连回自己（也避免自签名证书导致的 TLS 自校验失败）
        var local = recipients.Where(r => IsValidAddress(r) && store.IsLocalAddress(r)).ToArray();
        foreach (var recipient in local)
        {
            store.DeliverLocal(recipient, raw, message.From);
            AppLog.Info($"[发送] 本地投递完成：{recipient}");
        }

        var remote = recipients.Where(r => IsValidAddress(r) && !store.IsLocalAddress(r)).ToArray();
        if (remote.Length == 0) return;

        if (config.DeliveryMode.Equals("relay", StringComparison.OrdinalIgnoreCase))
        {
            var helo = string.IsNullOrWhiteSpace(config.DirectDelivery.HeloName) ? config.Hostname : config.DirectDelivery.HeloName;
            await SendAsync(config.Relay.Host, config.Relay.Port, message.From, remote, raw,
                startTls: config.Relay.EnableSsl, requireStartTls: config.Relay.EnableSsl,
                user: config.Relay.User, password: config.Relay.Password, helo: helo, token: token);
            return;
        }

        foreach (var group in remote.GroupBy(GetDomain, StringComparer.OrdinalIgnoreCase))
        {
            await DeliverDomainAsync(message.From, group.Key, group.ToArray(), raw, token);
        }
    }

    private async Task DeliverDomainAsync(string sender, string domain, string[] recipients, byte[] raw, CancellationToken token)
    {
        var mxHosts = await MxResolver.ResolveAsync(domain, config.DirectDelivery, token);
        if (mxHosts.Count == 0) throw new SmtpDeliveryException("MX 查询", 550, $"找不到 {domain} 的 MX 记录。", permanent: true);

        var helo = string.IsNullOrWhiteSpace(config.DirectDelivery.HeloName) ? config.Hostname : config.DirectDelivery.HeloName;
        Exception? last = null;

        foreach (var mxHost in mxHosts)
        {
            try
            {
                await SendAsync(mxHost, 25, sender, recipients, raw,
                    startTls: config.DirectDelivery.OpportunisticStartTls,
                    requireStartTls: config.DirectDelivery.RequireStartTls,
                    user: "", password: "", helo: helo, token: token);
                return;
            }
            catch (StartTlsFailedException ex) when (!config.DirectDelivery.RequireStartTls)
            {
                // 机会式 TLS：握手失败（例如对方证书不受信）时必须真正回退明文重连，
                // 否则一次证书问题就会导致永久投递失败。
                AppLog.Warn($"[发送] {mxHost} 的 STARTTLS 失败（{ex.Message}），改用明文重试同一 MX。");
                try
                {
                    await SendAsync(mxHost, 25, sender, recipients, raw,
                        startTls: false, requireStartTls: false,
                        user: "", password: "", helo: helo, token: token);
                    return;
                }
                catch (Exception inner) when (inner is IOException or SocketException or TimeoutException
                                              or InvalidOperationException or AuthenticationException or SmtpDeliveryException)
                {
                    last = inner;
                    AppLog.Warn($"[发送] MX {mxHost} 明文重试失败：{inner.Message}");
                }
            }
            catch (SmtpDeliveryException ex) when (ex.Permanent)
            {
                // 永久性拒绝：换下一个 MX 没有意义，直接上报
                throw;
            }
            catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or InvalidOperationException
                                       or AuthenticationException or StartTlsFailedException)
            {
                last = ex;
                AppLog.Warn($"[发送] MX {mxHost} 失败：{ex.Message}");
            }
        }

        if (last is SmtpDeliveryException smtp) throw smtp;
        throw new SmtpDeliveryException("投递", 451, $"无法投递到 {domain}：{last?.Message ?? "所有 MX 服务器均失败"}", permanent: false);
    }

    /// <summary>与某个 SMTP 服务器完成一次投递事务。</summary>
    private async Task SendAsync(string host, int port, string sender, string[] recipients, byte[] raw,
        bool startTls, bool requireStartTls, string user, string password, string helo, CancellationToken token)
    {
        var connectionTimeout = TimeSpan.FromSeconds(Math.Max(5, config.DirectDelivery.ConnectionTimeoutSeconds));
        var commandTimeout = TimeSpan.FromSeconds(Math.Max(5, config.DirectDelivery.CommandTimeoutSeconds));

        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(host, port, token).AsTask().WaitAsync(connectionTimeout, token);

        Stream stream = client.GetStream();
        var reader = NewReader(stream);
        var writer = NewWriter(stream);

        try
        {
            Expect(await ReadReplyAsync(reader, commandTimeout, token), "连接欢迎语", 220);

            var hello = await CommandAsync(reader, writer, $"EHLO {helo}", commandTimeout, token);
            if (hello.Code is < 200 or >= 300)
                Expect(await CommandAsync(reader, writer, $"HELO {helo}", commandTimeout, token), "HELO", 250);
            else if (startTls && HasCapability(hello, "STARTTLS"))
            {
                var startTlsReply = await CommandAsync(reader, writer, "STARTTLS", commandTimeout, token);
                if (startTlsReply.Code == 220)
                {
                    try
                    {
                        var ssl = new SslStream(stream, leaveInnerStreamOpen: false, (_, _, _, errors) => errors == SslPolicyErrors.None);
                        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                        {
                            TargetHost = host,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                        }, token).WaitAsync(commandTimeout, token);
                        stream = ssl;
                        reader = NewReader(stream);
                        writer = NewWriter(stream);
                        hello = await CommandAsync(reader, writer, $"EHLO {helo}", commandTimeout, token);
                    }
                    catch (Exception ex) when (ex is AuthenticationException or IOException)
                    {
                        if (requireStartTls)
                            throw new SmtpDeliveryException("STARTTLS", 451, $"{host} 的 TLS 握手失败（要求加密）：{ex.Message}", permanent: false);
                        throw new StartTlsFailedException(ex.Message);
                    }
                }
                else if (requireStartTls)
                {
                    throw new SmtpDeliveryException("STARTTLS", startTlsReply.Code, "对方拒绝 STARTTLS。", permanent: false);
                }
            }
            else if (requireStartTls)
            {
                throw new SmtpDeliveryException("STARTTLS", 451, "对方未广告 STARTTLS。", permanent: false);
            }

            // 中继模式需要认证
            if (!string.IsNullOrWhiteSpace(user))
            {
                var authPayload = Convert.ToBase64String(Encoding.UTF8.GetBytes("\0" + user + "\0" + password));
                var auth = await CommandAsync(reader, writer, "AUTH PLAIN " + authPayload, commandTimeout, token);
                if (auth.Code != 235) throw new SmtpDeliveryException("AUTH", auth.Code, auth.Detail, auth.Code is >= 500 and < 600);
            }

            Expect(await CommandAsync(reader, writer, $"MAIL FROM:<{NormalizeAddress(sender)}>", commandTimeout, token), "MAIL FROM", 250, 251);

            var accepted = new List<string>();
            foreach (var recipient in recipients)
            {
                var reply = await CommandAsync(reader, writer, $"RCPT TO:<{NormalizeAddress(recipient)}>", commandTimeout, token);
                if (reply.Code is 250 or 251) { accepted.Add(recipient); continue; }
                // 收件人被拒：5xx 视为这封邮件对该收件人永久失败
                throw new SmtpDeliveryException($"RCPT TO {recipient}", reply.Code, reply.Detail, reply.Code is >= 500 and < 600);
            }
            if (accepted.Count == 0) throw new SmtpDeliveryException("RCPT TO", 550, "所有收件人都被拒绝。", permanent: true);

            Expect(await CommandAsync(reader, writer, "DATA", commandTimeout, token), "DATA", 354);
            await WriteDataAsync(stream, raw, token);
            var result = await ReadReplyAsync(reader, commandTimeout, token);
            if (result.Code != 250)
                throw new SmtpDeliveryException("邮件正文", result.Code, result.Detail, result.Code is >= 500 and < 600);

            await TryQuitAsync(reader, writer, token);
        }
        finally
        {
            await stream.DisposeAsync();
        }
    }

    /// <summary>
    /// 写出 DATA 段。
    ///
    /// 这里是 v1 中文变 '?' 的根因所在（v1 用 Encoding.ASCII 的 StreamWriter 写），
    /// 现在改为按字节写出，且除 dot-stuffing 外不改动任何字节——
    /// 行尾规范化已在签名之前完成（见 SmtpDataEncoder.Normalize），
    /// 若在此处再改行尾会让 DKIM 正文哈希对不上。
    /// </summary>
    private static async Task WriteDataAsync(Stream stream, byte[] raw, CancellationToken token)
    {
        var payload = SmtpDataEncoder.Encode(SmtpDataEncoder.Normalize(raw));
        await stream.WriteAsync(payload, token);
        await stream.FlushAsync(token);
    }

    // ---------------------------------------------------------------- SMTP 会话

    private async Task<SmtpReply> CommandAsync(StreamReader reader, StreamWriter writer, string command, TimeSpan timeout, CancellationToken token)
    {
        await writer.WriteLineAsync(command).WaitAsync(timeout, token);
        return await ReadReplyAsync(reader, timeout, token);
    }

    private static async Task<SmtpReply> ReadReplyAsync(StreamReader reader, TimeSpan timeout, CancellationToken token)
    {
        var lines = new List<string>();
        var first = await reader.ReadLineAsync(token).AsTask().WaitAsync(timeout, token)
            ?? throw new IOException("SMTP 连接提前关闭。");
        lines.Add(first);
        if (first.Length < 3 || !int.TryParse(first[..3], out var code))
            throw new InvalidOperationException($"SMTP 返回无效响应：{first}");
        if (first.Length > 3 && first[3] == '-')
        {
            while (true)
            {
                var line = await reader.ReadLineAsync(token).AsTask().WaitAsync(timeout, token)
                    ?? throw new IOException("SMTP 多行响应提前结束。");
                lines.Add(line);
                if (line.StartsWith($"{code:D3} ", StringComparison.Ordinal)) break;
            }
        }
        return new SmtpReply(code, lines);
    }

    private static bool HasCapability(SmtpReply reply, string capability) =>
        reply.Lines.Any(x => x.Length > 4 && x[4..].StartsWith(capability, StringComparison.OrdinalIgnoreCase));

    private static void Expect(SmtpReply reply, string step, params int[] expected)
    {
        if (!expected.Contains(reply.Code))
            throw new SmtpDeliveryException(step, reply.Code, reply.Detail, reply.Code is >= 500 and < 600);
    }

    private static async Task TryQuitAsync(StreamReader reader, StreamWriter writer, CancellationToken token)
    {
        try
        {
            await writer.WriteLineAsync("QUIT").WaitAsync(TimeSpan.FromSeconds(5), token);
            await reader.ReadLineAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(5), token);
        }
        catch { }
    }

    // SMTP 控制通道只传 ASCII 命令，读响应也只需 ASCII；DATA 走字节通道，与此无关
    private static StreamReader NewReader(Stream stream) => new(stream, Encoding.ASCII, false, 8192, true);
    private static StreamWriter NewWriter(Stream stream) => new(stream, Encoding.ASCII, 8192, true) { AutoFlush = true, NewLine = "\r\n" };

    private static bool IsValidAddress(string value) =>
        value.Contains('@') && value.IndexOf('@') > 0 && value.IndexOf('@') < value.Length - 1;

    private static string GetDomain(string value) => value[(value.LastIndexOf('@') + 1)..].Trim().TrimEnd('.').ToLowerInvariant();
    private static string NormalizeAddress(string value) => value.Trim().Trim('<', '>');

    private sealed record SmtpReply(int Code, IReadOnlyList<string> Lines)
    {
        /// <summary>取最后一行去掉状态码后的文本，便于写入日志。</summary>
        public string Detail => Lines.Count == 0 ? "" : (Lines[^1].Length > 4 ? Lines[^1][4..] : Lines[^1]);
    }

    /// <summary>STARTTLS 握手失败（机会式 TLS 场景下应回退明文重连）。</summary>
    private sealed class StartTlsFailedException(string message) : Exception(message);
}

/// <summary>SMTP 阶段异常，带状态码与「是否永久失败」判定。</summary>
public sealed class SmtpDeliveryException : Exception
{
    public SmtpDeliveryException(string step, int code, string detail, bool permanent)
        : base($"{step} 失败：{code} {detail}")
    {
        Step = step;
        Code = code;
        Permanent = permanent;
    }

    public string Step { get; }
    public int Code { get; }
    public bool Permanent { get; }
}

/// <summary>极简 DNS MX 查询（不依赖第三方库，直接走 UDP 53）。</summary>
internal static class MxResolver
{
    public static async Task<IReadOnlyList<string>> ResolveAsync(string domain, DirectDeliveryConfig config, CancellationToken token)
    {
        foreach (var server in GetDnsServers(config.DnsServer))
        {
            try
            {
                var records = await QueryAsync(domain, server, config.DnsTimeoutSeconds, token);
                if (records.Count > 0) return records;
            }
            catch (Exception ex) when (ex is SocketException or TimeoutException or InvalidOperationException)
            {
                AppLog.Warn($"[DNS] 查询 {domain} 的 MX 失败（{server}）：{ex.Message}");
            }
        }

        // 没有 MX 记录时按 RFC 5321 回退到 A 记录
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain, token);
            return addresses.Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                            .Select(x => x.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
        }
        catch { return []; }
    }

    private static async Task<IReadOnlyList<string>> QueryAsync(string domain, IPAddress server, int timeoutSeconds, CancellationToken token)
    {
        using var udp = new UdpClient(server.AddressFamily);
        var query = BuildQuery(domain, out var id);
        await udp.SendAsync(query, query.Length, new IPEndPoint(server, 53));
        var result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(Math.Max(1, timeoutSeconds)), token);
        return ParseResponse(result.Buffer, id);
    }

    private static byte[] BuildQuery(string domain, out ushort id)
    {
        id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);
        writer.Write(ToNetwork(id));
        writer.Write(ToNetwork((ushort)0x0100)); // 标准查询，期望递归
        writer.Write(ToNetwork((ushort)1));
        writer.Write(ToNetwork((ushort)0));
        writer.Write(ToNetwork((ushort)0));
        writer.Write(ToNetwork((ushort)0));
        foreach (var label in domain.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)bytes.Length);
            writer.Write(bytes);
        }
        writer.Write((byte)0);
        writer.Write(ToNetwork((ushort)15)); // MX
        writer.Write(ToNetwork((ushort)1));  // IN
        return stream.ToArray();
    }

    private static IReadOnlyList<string> ParseResponse(byte[] data, ushort expectedId)
    {
        if (data.Length < 12 || ReadUInt16(data, 0) != expectedId) return [];
        var flags = ReadUInt16(data, 2);
        if ((flags & 0x8000) == 0 || (flags & 0x000F) != 0) return [];
        var questions = ReadUInt16(data, 4);
        var answers = ReadUInt16(data, 6);
        var authority = ReadUInt16(data, 8);
        var additional = ReadUInt16(data, 10);
        var offset = 12;
        for (var i = 0; i < questions; i++) { ReadName(data, ref offset); offset += 4; }

        var records = new List<(ushort Preference, string Host)>();
        for (var i = 0; i < answers + authority + additional && offset < data.Length; i++)
        {
            ReadName(data, ref offset);
            if (offset + 10 > data.Length) break;
            var type = ReadUInt16(data, offset);
            var cls = ReadUInt16(data, offset + 2);
            var length = ReadUInt16(data, offset + 8);
            offset += 10;
            if (offset + length > data.Length) break;
            if (type == 15 && cls == 1 && length >= 3)
            {
                var preference = ReadUInt16(data, offset);
                var nameOffset = offset + 2;
                var host = ReadName(data, ref nameOffset);
                if (!string.IsNullOrWhiteSpace(host)) records.Add((preference, host.TrimEnd('.')));
            }
            offset += length;
        }
        return records.OrderBy(x => x.Preference).Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string ReadName(byte[] data, ref int offset)
    {
        var labels = new List<string>();
        var cursor = offset;
        var jumped = false;
        var next = offset;
        while (cursor < data.Length)
        {
            var length = data[cursor++];
            if (length == 0) { if (!jumped) next = cursor; break; }
            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= data.Length) throw new InvalidOperationException("DNS 名称指针无效。");
                var pointer = ((length & 0x3F) << 8) | data[cursor++];
                if (!jumped) next = cursor;
                cursor = pointer;
                jumped = true;
                continue;
            }
            if (length > 63 || cursor + length > data.Length) throw new InvalidOperationException("DNS 名称长度无效。");
            labels.Add(Encoding.ASCII.GetString(data, cursor, length));
            cursor += length;
        }
        offset = next;
        return string.Join('.', labels);
    }

    private static ushort ReadUInt16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);
    private static ushort ToNetwork(ushort value) => (ushort)((value << 8) | (value >> 8));

    private static IReadOnlyList<IPAddress> GetDnsServers(string configured)
    {
        if (IPAddress.TryParse(configured, out var parsed)) return [parsed];
        var system = NetworkInterface.GetAllNetworkInterfaces()
            .Where(x => x.OperationalStatus == OperationalStatus.Up)
            .SelectMany(x => x.GetIPProperties().DnsAddresses)
            .Where(x => x.AddressFamily == AddressFamily.InterNetwork)
            .Distinct()
            .ToArray();
        return system.Length > 0 ? system : [IPAddress.Parse("223.5.5.5"), IPAddress.Parse("1.1.1.1")];
    }
}
