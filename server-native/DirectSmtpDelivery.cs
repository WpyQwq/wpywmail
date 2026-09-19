using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;

namespace WpywMail.Native;

public sealed class DirectSmtpDelivery
{
    private readonly AppConfig config;
    private readonly FileStore store;

    public DirectSmtpDelivery(AppConfig config, FileStore store)
    {
        this.config = config;
        this.store = store;
    }

    public async Task DeliverAsync(MailMessage message, string[] recipients, CancellationToken token)
    {
        if (recipients.Length == 0) throw new InvalidOperationException("没有可投递的收件人。");
        var raw = store.ReadRaw(message.RawPath);
        foreach (var group in recipients.Where(IsValidAddress).GroupBy(GetDomain, StringComparer.OrdinalIgnoreCase))
        {
            await DeliverDomainAsync(message.From, group.Key, group.ToArray(), raw, token);
        }
    }

    private async Task DeliverDomainAsync(string sender, string domain, string[] recipients, byte[] raw, CancellationToken token)
    {
        var mxHosts = await MxResolver.ResolveAsync(domain, config.DirectDelivery, token);
        if (mxHosts.Count == 0) throw new InvalidOperationException($"找不到 {domain} 的 MX 记录。");

        Exception? last = null;
        foreach (var mxHost in mxHosts)
        {
            try
            {
                await SendToMxAsync(mxHost, sender, recipients, raw, token, tryStartTls: true);
                return;
            }
            catch (StartTlsUnavailableException) when (!config.DirectDelivery.RequireStartTls)
            {
                try
                {
                    await SendToMxAsync(mxHost, sender, recipients, raw, token, tryStartTls: false);
                    return;
                }
                catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or InvalidOperationException or AuthenticationException)
                {
                    last = ex;
                    AppLog.Warn($"[发送] MX {mxHost} 明文重试失败：{ex.Message}");
                }
            }
            catch (Exception ex) when (ex is IOException or SocketException or TimeoutException or InvalidOperationException or AuthenticationException)
            {
                last = ex;
                AppLog.Warn($"[发送] MX {mxHost} 失败：{ex.Message}");
            }
        }

        throw new InvalidOperationException($"无法投递到 {domain}：{last?.Message ?? "所有 MX 服务器均失败"}");
    }

    private async Task SendToMxAsync(string mxHost, string sender, string[] recipients, byte[] raw, CancellationToken token, bool tryStartTls)
    {
        using var client = new TcpClient { NoDelay = true };
        await client.ConnectAsync(mxHost, 25, token).AsTask().WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.ConnectionTimeoutSeconds), token);
        Stream stream = client.GetStream();
        StreamReader reader = NewReader(stream);
        StreamWriter writer = NewWriter(stream);

        try
        {
            Expect(await ReadReplyAsync(reader, token), "连接欢迎语", 220);
            var hello = await CommandAsync(reader, writer, $"EHLO {config.Hostname}", token);
            if (hello.Code < 200 || hello.Code >= 300)
            {
                Expect(await CommandAsync(reader, writer, $"HELO {config.Hostname}", token), "HELO", 250);
            }
            else if (tryStartTls && config.DirectDelivery.OpportunisticStartTls && HasCapability(hello, "STARTTLS"))
            {
                var startTls = await CommandAsync(reader, writer, "STARTTLS", token);
                if (startTls.Code == 220)
                {
                    try
                    {
                        var ssl = new SslStream(stream, leaveInnerStreamOpen: false, ValidateCertificate);
                        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                        {
                            TargetHost = mxHost,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                        }, token).WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.CommandTimeoutSeconds), token);
                        stream = ssl;
                        reader = NewReader(stream);
                        writer = NewWriter(stream);
                        hello = await CommandAsync(reader, writer, $"EHLO {config.Hostname}", token);
                    }
                    catch (AuthenticationException) when (!config.DirectDelivery.RequireStartTls)
                    {
                        throw new StartTlsUnavailableException("对方 STARTTLS 证书验证失败。");
                    }
                }
                else if (config.DirectDelivery.RequireStartTls)
                {
                    throw new InvalidOperationException("对方 SMTP 不接受 STARTTLS。");
                }
            }
            else if (config.DirectDelivery.RequireStartTls)
            {
                throw new InvalidOperationException("对方 SMTP 未提供 STARTTLS。");
            }

            Expect(await CommandAsync(reader, writer, $"MAIL FROM:<{NormalizeAddress(sender)}>", token), "MAIL FROM", 250);
            foreach (var recipient in recipients)
            {
                Expect(await CommandAsync(reader, writer, $"RCPT TO:<{NormalizeAddress(recipient)}>", token), $"RCPT TO {recipient}", 250, 251);
            }

            Expect(await CommandAsync(reader, writer, "DATA", token), "DATA", 354);
            await WriteDataAsync(writer, raw, token);
            Expect(await ReadReplyAsync(reader, token), "邮件正文", 250);
            await TryQuitAsync(reader, writer, token);
        }
        finally
        {
            await stream.DisposeAsync();
        }
    }

    private async Task WriteDataAsync(StreamWriter writer, byte[] raw, CancellationToken token)
    {
        var text = Encoding.UTF8.GetString(raw).Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = text.Split('\n');
        for (var index = 0; index < lines.Length; index++)
        {
            if (index == lines.Length - 1 && lines[index].Length == 0) continue;
            var line = lines[index];
            if (line.StartsWith('.')) line = "." + line;
            await writer.WriteLineAsync(line).WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.CommandTimeoutSeconds), token);
        }
        await writer.WriteLineAsync(".").WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.CommandTimeoutSeconds), token);
    }

    private async Task<SmtpReply> CommandAsync(StreamReader reader, StreamWriter writer, string command, CancellationToken token)
    {
        await writer.WriteLineAsync(command).WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.CommandTimeoutSeconds), token);
        return await ReadReplyAsync(reader, token);
    }

    private async Task<SmtpReply> ReadReplyAsync(StreamReader reader, CancellationToken token)
    {
        var lines = new List<string>();
        var first = await reader.ReadLineAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.CommandTimeoutSeconds), token)
            ?? throw new IOException("SMTP 连接提前关闭。");
        lines.Add(first);
        if (first.Length < 3 || !int.TryParse(first[..3], out var code)) throw new InvalidOperationException($"SMTP 返回无效响应：{first}");
        if (first.Length > 3 && first[3] == '-')
        {
            while (true)
            {
                var line = await reader.ReadLineAsync(token).AsTask().WaitAsync(TimeSpan.FromSeconds(config.DirectDelivery.CommandTimeoutSeconds), token)
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
        if (!expected.Contains(reply.Code)) throw new SmtpDeliveryException(step, reply.Code, reply.Lines.LastOrDefault() ?? "");
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

    private static StreamReader NewReader(Stream stream) => new(stream, Encoding.ASCII, false, 8192, true);
    private static StreamWriter NewWriter(Stream stream) => new(stream, Encoding.ASCII, 8192, true) { AutoFlush = true, NewLine = "\r\n" };
    private static bool ValidateCertificate(object sender, System.Security.Cryptography.X509Certificates.X509Certificate? certificate, System.Security.Cryptography.X509Certificates.X509Chain? chain, SslPolicyErrors errors) => errors == SslPolicyErrors.None;
    private static bool IsValidAddress(string value) => value.Contains('@') && value.IndexOf('@') > 0 && value.IndexOf('@') < value.Length - 1;
    private static string GetDomain(string value) => value[(value.LastIndexOf('@') + 1)..].Trim().TrimEnd('.').ToLowerInvariant();
    private static string NormalizeAddress(string value) => value.Trim().Trim('<', '>');
    private sealed record SmtpReply(int Code, IReadOnlyList<string> Lines);
    private sealed class StartTlsUnavailableException(string message) : Exception(message);
}

public sealed class SmtpDeliveryException(string step, int code, string detail) : Exception($"{step} 失败：{code} {detail}")
{
    public int Code { get; } = code;
    public bool Permanent => Code >= 500 && Code <= 599;
}

internal static class MxResolver
{
    public static async Task<IReadOnlyList<string>> ResolveAsync(string domain, DirectDeliveryConfig config, CancellationToken token)
    {
        var servers = GetDnsServers(config.DnsServer);
        foreach (var server in servers)
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

        try
        {
            var addresses = await Dns.GetHostAddressesAsync(domain, token);
            return addresses.Select(x => x.ToString()).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
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
        writer.Write(ToNetwork(id)); writer.Write(ToNetwork((ushort)0x0100)); writer.Write(ToNetwork((ushort)1)); writer.Write(ToNetwork((ushort)0)); writer.Write(ToNetwork((ushort)0)); writer.Write(ToNetwork((ushort)0));
        foreach (var label in domain.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)bytes.Length); writer.Write(bytes);
        }
        writer.Write((byte)0); writer.Write(ToNetwork((ushort)15)); writer.Write(ToNetwork((ushort)1));
        return stream.ToArray();
    }

    private static IReadOnlyList<string> ParseResponse(byte[] data, ushort expectedId)
    {
        if (data.Length < 12 || ReadUInt16(data, 0) != expectedId) return [];
        var flags = ReadUInt16(data, 2);
        if ((flags & 0x8000) == 0 || (flags & 0x000F) != 0) return [];
        var questions = ReadUInt16(data, 4); var answers = ReadUInt16(data, 6); var authority = ReadUInt16(data, 8); var additional = ReadUInt16(data, 10);
        var offset = 12;
        for (var i = 0; i < questions; i++) { ReadName(data, ref offset); offset += 4; }
        var records = new List<(ushort Preference, string Host)>();
        for (var i = 0; i < answers + authority + additional && offset < data.Length; i++)
        {
            ReadName(data, ref offset);
            if (offset + 10 > data.Length) break;
            var type = ReadUInt16(data, offset); var cls = ReadUInt16(data, offset + 2); var length = ReadUInt16(data, offset + 8); offset += 10;
            if (offset + length > data.Length) break;
            if (type == 15 && cls == 1 && length >= 3)
            {
                var preference = ReadUInt16(data, offset); var nameOffset = offset + 2; var host = ReadName(data, ref nameOffset);
                if (!string.IsNullOrWhiteSpace(host)) records.Add((preference, host.TrimEnd('.')));
            }
            offset += length;
        }
        return records.OrderBy(x => x.Preference).Select(x => x.Host).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
    }

    private static string ReadName(byte[] data, ref int offset)
    {
        var labels = new List<string>(); var cursor = offset; var jumped = false; var next = offset;
        while (cursor < data.Length)
        {
            var length = data[cursor++];
            if (length == 0) { if (!jumped) next = cursor; break; }
            if ((length & 0xC0) == 0xC0)
            {
                if (cursor >= data.Length) throw new InvalidOperationException("DNS 名称指针无效。");
                var pointer = ((length & 0x3F) << 8) | data[cursor++];
                if (!jumped) next = cursor; cursor = pointer; jumped = true; continue;
            }
            if (length > 63 || cursor + length > data.Length) throw new InvalidOperationException("DNS 名称长度无效。");
            labels.Add(Encoding.ASCII.GetString(data, cursor, length)); cursor += length;
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
            .Where(x => x.AddressFamily == AddressFamily.InterNetwork || (x.AddressFamily == AddressFamily.InterNetworkV6 && !x.IsIPv6SiteLocal))
            .Distinct()
            .OrderBy(x => x.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();
        return system.Length > 0 ? system : [IPAddress.Parse("223.5.5.5"), IPAddress.Parse("1.1.1.1")];
    }
}
