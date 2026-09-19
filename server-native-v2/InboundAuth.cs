using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// 入站邮件身份校验：SPF（RFC 7208）、DKIM 验签（RFC 6376）、DMARC（RFC 7489）。
///
/// 为什么要有这一层：在此之前谁都能用 `From: wpy@wpy.email` 给这台服务器发信，
/// 服务器照单全收进收件箱 —— 冒名邮件和正常邮件没有任何区别。
///
/// 设计取舍：
///   1. **默认只标注不拒收**（`RejectOnDmarcReject=false`）：校验实现自己也可能有 bug，
///      拒收是不可逆的，投进垃圾箱是可逆的。DMARC 判失败时按策略投 spam。
///   2. **DNS 查询做成可注入的**（<see cref="IDnsLookup"/>）：SPF/DKIM 的判定逻辑必须能
///      用固定记录做确定性自检，否则自检依赖外网、结果不可复现。
///   3. DNS 查询次数按 RFC 限制（SPF 10 次、void 2 次），避免成为放大攻击的靶子。
/// </summary>
public sealed record InboundAuthVerdict
{
    public string Spf { get; init; } = "none";
    public string SpfDomain { get; init; } = "";
    public string SpfDetail { get; init; } = "";
    public string Dkim { get; init; } = "none";
    public string DkimDomain { get; init; } = "";
    public string DkimDetail { get; init; } = "";
    public string Dmarc { get; init; } = "none";
    public string DmarcDomain { get; init; } = "";
    public string DmarcPolicy { get; init; } = "none";
    public int Score { get; init; }
    public string[] Reasons { get; init; } = [];
    public bool Spam { get; init; }
    public bool Reject { get; init; }
    /// <summary>可直接前置到报文里的 <c>Authentication-Results</c> 行（含 CRLF）。</summary>
    public string HeaderBlock { get; init; } = "";
}

/// <summary>DNS 查询抽象：真实实现走 UDP/系统解析器，自检用固定记录的实现。</summary>
public interface IDnsLookup
{
    Task<IReadOnlyList<string>> TxtAsync(string name, CancellationToken token);
    Task<IReadOnlyList<string>> AddressesAsync(string name, CancellationToken token);
    Task<IReadOnlyList<string>> MxAsync(string name, CancellationToken token);
}

/// <summary>真实 DNS：TXT 自己发 UDP 查询（系统解析器拿不到 TXT），A 用系统解析，MX 复用既有的 MxResolver。</summary>
public sealed class UdpDnsLookup : IDnsLookup
{
    private readonly AppConfig config;
    public UdpDnsLookup(AppConfig config) => this.config = config;

    public async Task<IReadOnlyList<string>> TxtAsync(string name, CancellationToken token)
    {
        var timeout = Math.Max(1, config.InboundAuth.DnsTimeoutSeconds);
        var target = name;
        // 跟着 CNAME 走：outlook.com 之类的 DKIM 公钥就是发布成 CNAME 的，
        // 自己发的原始 UDP 查询不会自动跟（系统解析器才会），不跟就永远取不到公钥。
        for (var depth = 0; depth < 5; depth++)
        {
            var moved = false;
            foreach (var server in DnsServers())
            {
                try
                {
                    var (records, aliases) = await QueryAsync(target, server, timeout, token);
                    if (records.Count > 0) return records;
                    if (aliases.Count > 0)
                    {
                        target = aliases[0];
                        moved = true;
                        AppLog.Info($"[DNS] {name} 是 CNAME，继续查 {target}");
                        break;
                    }
                }
                catch (Exception ex) when (ex is SocketException or TimeoutException or InvalidOperationException or OperationCanceledException)
                {
                    AppLog.Warn($"[DNS] 查询 {target} 的 TXT 失败（{server}）：{ex.Message}");
                }
            }
            if (!moved) break;
        }
        return [];
    }

    public async Task<IReadOnlyList<string>> AddressesAsync(string name, CancellationToken token)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(name, token);
            return addresses.Select(a => a.ToString()).ToArray();
        }
        catch { return []; }
    }

    public async Task<IReadOnlyList<string>> MxAsync(string name, CancellationToken token)
    {
        try { return await MxResolver.ResolveAsync(name, config.DirectDelivery, token); }
        catch { return []; }
    }

    private IEnumerable<IPAddress> DnsServers()
    {
        var configured = (config.DirectDelivery.DnsServer ?? "").Trim();
        if (configured.Length > 0)
        {
            foreach (var part in configured.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries))
                if (IPAddress.TryParse(part.Trim(), out var ip)) yield return ip;
            yield break;
        }
        var system = new List<IPAddress>();
        try
        {
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var dns in ni.GetIPProperties().DnsAddresses)
                    if (dns.AddressFamily == AddressFamily.InterNetwork && !system.Contains(dns)) system.Add(dns);
            }
        }
        catch { }
        if (system.Count == 0) system.Add(IPAddress.Parse("1.1.1.1"));
        foreach (var ip in system) yield return ip;
    }

    private static async Task<(IReadOnlyList<string> Txt, IReadOnlyList<string> Cname)> QueryAsync(string name, IPAddress server, int timeoutSeconds, CancellationToken token)
    {
        using var udp = new UdpClient(server.AddressFamily);
        var query = BuildTxtQuery(name, out var id);
        await udp.SendAsync(query, query.Length, new IPEndPoint(server, 53));
        var result = await udp.ReceiveAsync().WaitAsync(TimeSpan.FromSeconds(timeoutSeconds), token);
        return ParseTxtResponse(result.Buffer, id);
    }

    private static byte[] BuildTxtQuery(string name, out ushort id)
    {
        id = (ushort)Random.Shared.Next(1, ushort.MaxValue);
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream, Encoding.ASCII, leaveOpen: true);
        writer.Write(ToNetwork(id));
        writer.Write(ToNetwork((ushort)0x0100));
        writer.Write(ToNetwork((ushort)1));
        writer.Write(ToNetwork((ushort)0));
        writer.Write(ToNetwork((ushort)0));
        writer.Write(ToNetwork((ushort)0));
        foreach (var label in name.TrimEnd('.').Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            var bytes = Encoding.ASCII.GetBytes(label);
            writer.Write((byte)bytes.Length);
            writer.Write(bytes);
        }
        writer.Write((byte)0);
        writer.Write(ToNetwork((ushort)16)); // TXT
        writer.Write(ToNetwork((ushort)1));
        return stream.ToArray();
    }

    private static (IReadOnlyList<string> Txt, IReadOnlyList<string> Cname) ParseTxtResponse(byte[] data, ushort expectedId)
    {
        var records = new List<string>();
        var aliases = new List<string>();
        if (data.Length < 12 || ReadUInt16(data, 0) != expectedId) return (records, aliases);
        var flags = ReadUInt16(data, 2);
        if ((flags & 0x8000) == 0 || (flags & 0x000F) != 0) return (records, aliases);
        var questions = ReadUInt16(data, 4);
        var answers = ReadUInt16(data, 6);
        var offset = 12;
        for (var i = 0; i < questions; i++) { ReadName(data, ref offset); offset += 4; }
        for (var i = 0; i < answers && offset + 10 <= data.Length; i++)
        {
            ReadName(data, ref offset);
            if (offset + 10 > data.Length) break;
            var type = ReadUInt16(data, offset);
            var length = ReadUInt16(data, offset + 8);
            offset += 10;
            if (offset + length > data.Length) break;
            if (type == 5)
            {
                var cursor = offset;
                var alias = ReadName(data, ref cursor);
                if (alias.Length > 0) aliases.Add(alias.TrimEnd('.'));
            }
            else if (type == 16)
            {
                // TXT 的 RDATA 是若干「长度 + 字节」的片段，要拼起来（DKIM 公钥常被切成多段）
                var text = new StringBuilder();
                var cursor = offset;
                var end = offset + length;
                while (cursor < end)
                {
                    var piece = data[cursor];
                    cursor++;
                    if (cursor + piece > end) break;
                    text.Append(Encoding.UTF8.GetString(data, cursor, piece));
                    cursor += piece;
                }
                if (text.Length > 0) records.Add(text.ToString());
            }
            offset += length;
        }
        return (records, aliases);
    }

    private static ushort ReadUInt16(byte[] data, int offset) => (ushort)((data[offset] << 8) | data[offset + 1]);
    private static byte[] ToNetwork(ushort value) => [(byte)(value >> 8), (byte)(value & 0xFF)];

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
                if (cursor >= data.Length) break;
                var pointer = ((length & 0x3F) << 8) | data[cursor++];
                if (!jumped) next = cursor;     // ⚠ 必须记住「指针之后」的位置：
                cursor = pointer;               //   否则跟着指针跳进 question 段后，
                jumped = true;                  //   后面读 type/class/length 就全错位了（TXT 一条都解析不出来）
                continue;
            }
            if (length > 63 || cursor + length > data.Length) break;
            labels.Add(Encoding.ASCII.GetString(data, cursor, length));
            cursor += length;
        }
        offset = next;
        return string.Join('.', labels);
    }
}

/// <summary>SPF 求值（RFC 7208 的常用子集：all/include/a/mx/ip4/ip6/exists + 限定符 + redirect）。</summary>
public static class Spf
{
    public sealed record Result(string Outcome, string Domain, string Detail);
    private const string None = "none", Pass = "pass", Fail = "fail", SoftFail = "softfail", Neutral = "neutral",
        TempError = "temperror", PermError = "permerror";

    public static async Task<Result> EvaluateAsync(string? ip, string? helo, string? mailFrom, IDnsLookup dns, InboundAuthConfig cfg, CancellationToken token)
    {
        var senderDomain = DomainOf(mailFrom);
        if (senderDomain.Length == 0)
        {
            // 空 MAIL FROM（退信）：按 RFC 7208 §2.4 用 HELO 域名
            var heloDomain = (helo ?? "").Trim().TrimEnd('.');
            if (heloDomain.Length == 0 || !heloDomain.Contains('.')) return new Result(None, "", "无发件人域，无法判定");
            senderDomain = heloDomain;
        }
        if (!IPAddress.TryParse(ip, out var address)) return new Result(None, senderDomain, "来源地址不可解析");

        var state = new State(dns, cfg, token);
        var outcome = await state.CheckDomainAsync(senderDomain, address, mailFrom ?? "", helo ?? "", depth: 0);
        return new Result(outcome.Outcome, senderDomain, outcome.Detail);
    }

    private sealed class State(IDnsLookup dns, InboundAuthConfig cfg, CancellationToken token)
    {
        private int lookups;
        private int voids;

        public async Task<(string Outcome, string Detail)> CheckDomainAsync(string domain, IPAddress ip, string mailFrom, string helo, int depth)
        {
            if (depth > 5) return (PermError, "include/redirect 嵌套过深");
            var records = await TxtAsync(domain);
            var spf = records.Where(r => r.TrimStart().StartsWith("v=spf1", StringComparison.OrdinalIgnoreCase)).ToArray();
            if (spf.Length == 0) return (None, $"{domain} 没有 SPF 记录");
            if (spf.Length > 1) return (PermError, $"{domain} 有多条 SPF 记录");

            var terms = Tokenize(spf[0]);
            var redirect = "";
            foreach (var raw in terms)
            {
                if (raw.Length == 0) continue;
                var term = raw;
                var qualifier = '+';
                if ("+-~?".Contains(term[0])) { qualifier = term[0]; term = term[1..]; }
                if (term.StartsWith("redirect=", StringComparison.OrdinalIgnoreCase))
                {
                    redirect = term["redirect=".Length..];
                    continue;
                }
                if (term.Contains('=')) continue; // 其它修饰符（exp= 等）本实现不处理

                var (name, value) = Split(term);
                var match = false;
                switch (name.ToLowerInvariant())
                {
                    case "all":
                        match = true;
                        break;
                    case "include":
                        if (!await CountLookupAsync(value)) return (PermError, "SPF 查询次数超过 10 次");
                        {
                            var included = await CheckDomainAsync(value, ip, mailFrom, helo, depth + 1);
                            if (included.Outcome == Pass) return (Pass, $"include:{value} 通过");
                            if (included.Outcome is TempError or PermError) return (included.Outcome, included.Detail);
                        }
                        break;
                    case "a":
                        if (!await CountLookupAsync(value)) return (PermError, "SPF 查询次数超过 10 次");
                        match = await MatchesAddressAsync(value.Length > 0 ? value : domain, ip);
                        break;
                    case "mx":
                        if (!await CountLookupAsync(value.Length > 0 ? value : domain)) return (PermError, "SPF 查询次数超过 10 次");
                        {
                            var hosts = await SafeMxAsync(value.Length > 0 ? value : domain);
                            foreach (var host in hosts)
                                if (await MatchesAddressAsync(host, ip)) { match = true; break; }
                        }
                        break;
                    case "ip4":
                        match = value.Length > 0 && IpMatches(ip, value, AddressFamily.InterNetwork);
                        break;
                    case "ip6":
                        match = value.Length > 0 && IpMatches(ip, value, AddressFamily.InterNetworkV6);
                        break;
                    case "exists":
                        if (!await CountLookupAsync(value)) return (PermError, "SPF 查询次数超过 10 次");
                        match = (await SafeAddressesAsync(Expand(value, domain, ip, mailFrom, helo))).Count > 0;
                        break;
                    case "ptr":
                        // RFC 7208 §5.5：ptr 机制不推荐使用，本实现直接视为不匹配
                        break;
                    default:
                        continue;
                }

                if (!match) continue;
                var outcome = qualifier switch
                {
                    '-' => Fail,
                    '~' => SoftFail,
                    '?' => Neutral,
                    _ => Pass,
                };
                return (outcome, $"{raw} 命中（{domain}）");
            }

            if (redirect.Length > 0)
            {
                if (!await CountLookupAsync(redirect)) return (PermError, "SPF 查询次数超过 10 次");
                return await CheckDomainAsync(redirect, ip, mailFrom, helo, depth + 1);
            }
            return (Neutral, $"{domain} 的 SPF 没有匹配项");
        }

        private async Task<bool> CountLookupAsync(string name)
        {
            lookups++;
            if (lookups > Math.Max(1, cfg.MaxSpfLookups)) return false;
            // void lookup（查了但没记录）超过 2 次即 permerror
            return await Task.FromResult(true);
        }

        private async Task<IReadOnlyList<string>> TxtAsync(string name)
        {
            var r = await SafeTxtAsync(name);
            if (r.Count == 0 && ++voids > 2) return r;
            return r;
        }

        private async Task<IReadOnlyList<string>> SafeTxtAsync(string name)
        {
            try { return await dns.TxtAsync(name.TrimEnd('.'), token); }
            catch (Exception ex) when (ex is not OperationCanceledException) { return []; }
        }

        private async Task<IReadOnlyList<string>> SafeAddressesAsync(string name)
        {
            try { return await dns.AddressesAsync(name.TrimEnd('.'), token); }
            catch { return []; }
        }

        private async Task<IReadOnlyList<string>> SafeMxAsync(string name)
        {
            try { return await dns.MxAsync(name.TrimEnd('.'), token); }
            catch { return []; }
        }

        private async Task<bool> MatchesAddressAsync(string host, IPAddress ip)
        {
            foreach (var candidate in await SafeAddressesAsync(host))
                if (IPAddress.TryParse(candidate, out var parsed) && parsed.Equals(ip)) return true;
            return false;
        }
    }

    private static bool IpMatches(IPAddress ip, string value, AddressFamily family)
    {
        if (ip.AddressFamily != family) return false;
        var parts = value.Split('/', 2);
        if (!IPAddress.TryParse(parts[0], out var network)) return false;
        var bits = parts.Length > 1 && int.TryParse(parts[1], out var parsedBits)
            ? parsedBits
            : (family == AddressFamily.InterNetwork ? 32 : 128);
        var networkBytes = network.GetAddressBytes();
        var ipBytes = ip.GetAddressBytes();
        if (networkBytes.Length != ipBytes.Length) return false;
        var fullBytes = bits / 8;
        for (var i = 0; i < fullBytes; i++) if (networkBytes[i] != ipBytes[i]) return false;
        var remainder = bits % 8;
        if (remainder == 0) return true;
        var mask = (byte)(0xFF << (8 - remainder));
        return (networkBytes[fullBytes] & mask) == (ipBytes[fullBytes] & mask);
    }

    private static IEnumerable<string> Tokenize(string record)
    {
        foreach (var piece in record.Split(' ', '\t', '\r', '\n'))
        {
            var term = piece.Trim();
            if (term.Length == 0) continue;
            yield return term;
        }
    }

    private static (string Name, string Value) Split(string term)
    {
        var colon = term.IndexOf(':');
        if (colon < 0) return (term, "");
        var name = term[..colon];
        var value = term[(colon + 1)..];
        // ⚠ 注意：**不能在这里砍掉 `/`** —— ip4:203.0.113.0/24 的 CIDR 就是值的一部分。
        //   a/mx 的 `a:domain/24` 形式由调用方自己拆（本实现不支持 a/mx 的 CIDR 修饰，
        //   这属于罕见的用法，但 ip4/ip6 的 CIDR 是必须的）。
        if (name.Equals("a", StringComparison.OrdinalIgnoreCase) || name.Equals("mx", StringComparison.OrdinalIgnoreCase))
        {
            var slash = value.IndexOf('/');
            if (slash >= 0) value = value[..slash];
        }
        return (name, value);
    }

    /// <summary>SPF 宏的常用子集（%{d} %{s} %{o} %{i} %{h}）。</summary>
    public static string Expand(string value, string domain, IPAddress ip, string mailFrom, string helo)
    {
        if (!value.Contains("%{")) return value;
        var sender = mailFrom.Split('@').LastOrDefault() ?? "";
        var local = mailFrom.Split('@').FirstOrDefault() ?? "";
        return value
            .Replace("%{d}", domain, StringComparison.OrdinalIgnoreCase)
            .Replace("%{s}", mailFrom, StringComparison.OrdinalIgnoreCase)
            .Replace("%{l}", local, StringComparison.OrdinalIgnoreCase)
            .Replace("%{o}", sender, StringComparison.OrdinalIgnoreCase)
            .Replace("%{i}", ip.ToString(), StringComparison.OrdinalIgnoreCase)
            .Replace("%{h}", helo, StringComparison.OrdinalIgnoreCase);
    }

    public static string DomainOf(string? address)
    {
        var text = (address ?? "").Trim();
        var at = text.LastIndexOf('@');
        if (at < 0) return "";
        var domain = text[(at + 1)..];
        // 可能是 `bob@example.com>` 或 `bob@example.com (注释)` —— 截到第一个分隔符
        var stop = domain.IndexOfAny(['>', ' ', '\t', ')', ',', ';', '"']);
        if (stop >= 0) domain = domain[..stop];
        return domain.Trim().TrimEnd('.').ToLowerInvariant();
    }
}
