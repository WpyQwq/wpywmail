using System.Security.Cryptography;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// DKIM 验签（RFC 6376）。**独立按 RFC 实现，不复用签名端代码** ——
/// 2026-09-13 那次 DKIM 顺序 bug 的教训就是「自己验自己」会一起错。
/// </summary>
public static class DkimVerifier
{
    public sealed record Result(string Outcome, string Domain, string Selector, string Detail);

    public static async Task<IReadOnlyList<Result>> VerifyAllAsync(byte[] raw, IDnsLookup dns, CancellationToken token)
    {
        var text = Encoding.Latin1.GetString(raw);      // 1 字节 ↔ 1 字符，索引即字节偏移
        var headers = ParseHeaders(text);
        var results = new List<Result>();
        foreach (var header in headers.Where(h => h.Name.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase)))
        {
            try { results.Add(await VerifyOneAsync(text, headers, header, dns, token)); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                results.Add(new Result("temperror", "", "", ex.Message));
            }
        }
        return results;
    }

    private sealed record Header(string Name, string Raw, string Value)
    {
        public bool Used { get; set; }
    }

    private static async Task<Result> VerifyOneAsync(string text, List<Header> headers, Header signature, IDnsLookup dns, CancellationToken token)
    {
        var tags = ParseTags(signature.Value);
        var domain = tags.GetValueOrDefault("d", "");
        var selector = tags.GetValueOrDefault("s", "");
        if (tags.GetValueOrDefault("v", "1") != "1") return new Result("fail", domain, selector, "v= 不是 1");
        if (domain.Length == 0 || selector.Length == 0) return new Result("fail", domain, selector, "缺 d= 或 s=");

        var algorithm = tags.GetValueOrDefault("a", "rsa-sha256").ToLowerInvariant();
        var hashName = algorithm switch
        {
            "rsa-sha256" => HashAlgorithmName.SHA256,
            "rsa-sha1" => HashAlgorithmName.SHA1,
            "ed25519-sha256" => HashAlgorithmName.SHA256,
            _ => default,
        };
        if (hashName == default) return new Result("fail", domain, selector, $"不支持的算法 a={algorithm}");
        if (algorithm.StartsWith("ed25519", StringComparison.Ordinal))
            return new Result("neutral", domain, selector, "ed25519 本实现不支持（极少见）");

        var canon = tags.GetValueOrDefault("c", "simple/simple").ToLowerInvariant().Split('/');
        var headerCanon = canon[0] is "relaxed" ? "relaxed" : "simple";
        var bodyCanon = canon.Length > 1 && canon[1] == "relaxed" ? "relaxed" : "simple";

        var body = ExtractBody(text);
        var canonicalBody = CanonicalizeBody(body, bodyCanon);
        if (tags.TryGetValue("l", out var lengthText) && int.TryParse(lengthText, out var limit) && limit >= 0 && limit < canonicalBody.Length)
            canonicalBody = canonicalBody[..limit];

        var expectedBodyHash = tags.GetValueOrDefault("bh", "");
        var actualBodyHash = Convert.ToBase64String(Hash(hashName, Encoding.Latin1.GetBytes(canonicalBody)));
        if (!string.Equals(expectedBodyHash, actualBodyHash, StringComparison.Ordinal))
            return new Result("fail", domain, selector, $"正文哈希不符（bh={Short(expectedBodyHash)} 实际={Short(actualBodyHash)}）");

        // 按 h= 的先后顺序取头，重名时从**下往上**取（RFC 6376 §5.4.2）
        var signedNames = tags.GetValueOrDefault("h", "").Split(':', StringSplitOptions.RemoveEmptyEntries);
        if (signedNames.Length == 0) return new Result("fail", domain, selector, "h= 为空");
        var builder = new StringBuilder();
        foreach (var name in signedNames)
        {
            var picked = headers.LastOrDefault(h => !h.Used && !ReferenceEquals(h, signature)
                && h.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase));
            if (picked is not null) picked.Used = true;
            builder.Append(CanonicalizeHeader(picked?.Name ?? name.Trim(), picked?.Raw ?? "", headerCanon));
        }
        builder.Append(CanonicalizeHeader(signature.Name, StripSignatureValue(signature.Raw), headerCanon, trimCrLf: true));

        var signatureBytes = Convert.FromBase64String(tags.GetValueOrDefault("b", "").Trim());
        var data = Encoding.Latin1.GetBytes(builder.ToString());

        var keyText = await LookupKeyAsync(domain, selector, dns, token);
        if (keyText is null) return new Result("temperror", domain, selector, $"取不到公钥 {selector}._domainkey.{domain}");
        if (keyText.Length == 0) return new Result("fail", domain, selector, "公钥记录里 p= 为空（已吊销）");

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(Convert.FromBase64String(keyText), out _);
            var ok = rsa.VerifyData(data, signatureBytes, hashName, RSASignaturePadding.Pkcs1);
            return ok
                ? new Result("pass", domain, selector, $"a={algorithm} c={string.Join('/', canon)}")
                : new Result("fail", domain, selector, "签名不符（报文可能被改过）");
        }
        catch (FormatException)
        {
            return new Result("fail", domain, selector, "公钥不是合法的 SPKI base64");
        }
        catch (CryptographicException ex)
        {
            return new Result("fail", domain, selector, $"验签异常：{ex.Message}");
        }
    }

    private static async Task<string?> LookupKeyAsync(string domain, string selector, IDnsLookup dns, CancellationToken token)
    {
        var name = $"{selector}._domainkey.{domain}";
        var records = await dns.TxtAsync(name, token);
        foreach (var record in records)
        {
            var tags = ParseTags(record);
            if (!tags.ContainsKey("p")) continue;
            return tags["p"];
        }
        return null;
    }

    private static string ExtractBody(string text)
    {
        var crlf = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var lf = text.IndexOf("\n\n", StringComparison.Ordinal);
        var index = crlf >= 0 && (lf < 0 || crlf <= lf) ? crlf + 4 : lf >= 0 ? lf + 2 : -1;
        return index < 0 ? "" : text[index..];
    }

    private static List<Header> ParseHeaders(string text)
    {
        var list = new List<Header>();
        var block = text;
        var crlf = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var lf = text.IndexOf("\n\n", StringComparison.Ordinal);
        if (crlf >= 0 && (lf < 0 || crlf <= lf)) block = text[..crlf];
        else if (lf >= 0) block = text[..lf];

        var lines = block.Split('\n');
        StringBuilder? current = null;
        foreach (var rawLine in lines)
        {
            var line = rawLine.TrimEnd('\r');
            if (line.Length == 0) continue;
            if ((line[0] == ' ' || line[0] == '\t') && current is not null)
            {
                current.Append("\r\n").Append(line);
                continue;
            }
            if (current is not null) list.Add(Finish(current.ToString()));
            current = new StringBuilder(line);
        }
        if (current is not null) list.Add(Finish(current.ToString()));
        return list;

        static Header Finish(string raw)
        {
            var colon = raw.IndexOf(':');
            if (colon < 0) return new Header(raw.Trim(), raw, "");
            var name = raw[..colon].Trim();
            var value = raw[(colon + 1)..].Trim();
            return new Header(name, raw, value);
        }
    }

    /// <summary>
    /// 把 b= 的值抹掉（验签输入里的 DKIM-Signature 头不能带签名本身）。
    ///
    /// ⚠ 必须**按标签边界**找 b=：直接 IndexOf("b=") 会被前面的 `bh=` 的 base64 内容误伤
    ///   （base64 以 `b=` 结尾完全合法），一位之差就整封验不过 —— 自检里正是这一条抓出来的。
    /// </summary>
    private static string StripSignatureValue(string raw)
    {
        var index = TagValueStart(raw, "b");
        if (index < 0) return raw;
        var end = raw.IndexOf(';', index);
        var head = raw[..index];
        var tail = end < 0 ? "" : raw[end..];
        return head + tail;
    }

    /// <summary>返回名为 name 的标签「值」的起始下标（-1 表示没有）。标签必须出现在 `;` 之后或开头。</summary>
    private static int TagValueStart(string raw, string name)
    {
        var position = raw.IndexOf(':');
        position = position < 0 ? 0 : position + 1;
        while (position < raw.Length)
        {
            while (position < raw.Length && (raw[position] is ' ' or '\t' or '\r' or '\n' or ';')) position++;
            if (position >= raw.Length) return -1;
            var equals = raw.IndexOf('=', position);
            if (equals < 0) return -1;
            var tag = raw[position..equals].Trim();
            var semicolon = raw.IndexOf(';', equals);
            if (tag.Equals(name, StringComparison.OrdinalIgnoreCase)) return equals + 1;
            if (semicolon < 0) return -1;
            position = semicolon + 1;
        }
        return -1;
    }

    private static string CanonicalizeHeader(string name, string raw, string mode, bool trimCrLf = false)
    {
        string result;
        if (mode == "relaxed")
        {
            var colon = raw.IndexOf(':');
            var value = colon < 0 ? "" : raw[(colon + 1)..];
            var unfolded = value.Replace("\r\n", " ");
            var collapsed = Collapse(unfolded).TrimEnd(' ', '\t');
            result = name.ToLowerInvariant().Trim() + ":" + collapsed + "\r\n";
        }
        else
        {
            var text = raw.Length > 0 ? raw : name + ":";
            result = text + "\r\n";
        }
        return trimCrLf ? result[..^2] : result;
    }

    private static string CanonicalizeBody(string body, string mode)
    {
        if (body.Length == 0) return "";
        var lines = new List<string>();
        var start = 0;
        while (start <= body.Length)
        {
            var end = body.IndexOf('\n', start);
            var hasTerminator = end >= 0;
            var line = hasTerminator ? body[start..end].TrimEnd('\r') : body[start..];
            lines.Add(line);
            if (!hasTerminator) break;
            start = end + 1;
        }
        // 去掉末尾的空行（保留最后一行的行尾）
        while (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
        if (lines.Count == 0) return "";

        var builder = new StringBuilder();
        for (var i = 0; i < lines.Count; i++)
        {
            var line = lines[i];
            if (mode == "relaxed")
            {
                line = Collapse(line).TrimEnd(' ', '\t');
            }
            builder.Append(line).Append("\r\n");
        }
        return builder.ToString();
    }

    private static string Collapse(string value)
    {
        var builder = new StringBuilder(value.Length);
        var space = false;
        foreach (var c in value)
        {
            if (c is ' ' or '\t')
            {
                space = true;
                continue;
            }
            if (space && builder.Length > 0) builder.Append(' ');
            space = false;
            builder.Append(c);
        }
        return builder.ToString();
    }

    private static byte[] Hash(HashAlgorithmName name, byte[] data) =>
        name == HashAlgorithmName.SHA1 ? SHA1.HashData(data) : SHA256.HashData(data);

    private static string Short(string value) => value.Length <= 10 ? value : value[..10] + "…";

    /// <summary>解析 `k=v; k=v` 形式的标签（DKIM 签名头与 DNS 公钥记录共用）。</summary>
    public static Dictionary<string, string> ParseTags(string text)
    {
        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in text.Split(';'))
        {
            var equals = part.IndexOf('=');
            if (equals <= 0) continue;
            var key = part[..equals].Trim().ToLowerInvariant();
            var value = part[(equals + 1)..];
            // 值里的换行/空白都要去掉（b=、p= 常被折成多行）
            value = new string(value.Where(c => c is not (' ' or '\t' or '\r' or '\n')).ToArray());
            if (key.Length > 0) tags[key] = value;
        }
        return tags;
    }
}

/// <summary>DMARC 求值（RFC 7489 的常用子集）。</summary>
public static class Dmarc
{
    public sealed record Result(string Outcome, string Policy, string Domain, string Detail);

    /// <summary>公共后缀的常用子集（判断「组织域」用；没列到的按最后两段算）。</summary>
    private static readonly HashSet<string> MultiPartSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "co.uk", "org.uk", "me.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp",
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "com.hk", "com.tw", "com.au",
        "com.br", "com.sg", "co.kr", "com.mx", "co.in", "com.tr",
    };

    /// <summary>组织域（relaxed 对齐用）：`mail.example.co.uk` → `example.co.uk`。</summary>
    public static string OrganizationalDomain(string domain)
    {
        var parts = (domain ?? "").Trim().TrimEnd('.').ToLowerInvariant().Split('.', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length <= 2) return string.Join('.', parts);
        var lastTwo = string.Join('.', parts[^2..]);
        return MultiPartSuffixes.Contains(lastTwo) && parts.Length >= 3
            ? string.Join('.', parts[^3..])
            : lastTwo;
    }

    public static async Task<Result> EvaluateAsync(string fromDomain, (string Outcome, string Domain) spf,
        IReadOnlyList<(string Outcome, string Domain)> dkims, IDnsLookup dns, CancellationToken token)
    {
        fromDomain = (fromDomain ?? "").Trim().TrimEnd('.').ToLowerInvariant();
        if (fromDomain.Length == 0) return new Result("none", "none", "", "报文没有可用的 From 域名");

        var records = await dns.TxtAsync("_dmarc." + fromDomain, token);
        var record = records.FirstOrDefault(r => r.TrimStart().StartsWith("v=DMARC1", StringComparison.OrdinalIgnoreCase));
        if (record is null) return new Result("none", "none", fromDomain, $"_dmarc.{fromDomain} 没有 DMARC 记录");

        var tags = DkimVerifier.ParseTags(record);
        var policy = tags.GetValueOrDefault("p", "").ToLowerInvariant();
        if (policy is not ("none" or "quarantine" or "reject"))
            return new Result("none", "none", fromDomain, $"DMARC 记录里的 p= 无效：{policy}");
        var strictSpf = tags.GetValueOrDefault("aspf", "r").Equals("s", StringComparison.OrdinalIgnoreCase);
        var strictDkim = tags.GetValueOrDefault("adkim", "r").Equals("s", StringComparison.OrdinalIgnoreCase);

        bool Aligned(string candidate, bool strict)
        {
            if (candidate.Length == 0) return false;
            return strict
                ? candidate.Equals(fromDomain, StringComparison.OrdinalIgnoreCase)
                : OrganizationalDomain(candidate) == OrganizationalDomain(fromDomain);
        }

        if (spf.Outcome == "pass" && Aligned(spf.Domain, strictSpf))
            return new Result("pass", policy, fromDomain, $"SPF 对齐通过（{spf.Domain}，aspf={(strictSpf ? "s" : "r")}）");
        foreach (var dkim in dkims.Where(d => d.Outcome == "pass"))
            if (Aligned(dkim.Domain, strictDkim))
                return new Result("pass", policy, fromDomain, $"DKIM 对齐通过（{dkim.Domain}，adkim={(strictDkim ? "s" : "r")}）");

        // 没有任何对齐的通过项 → 失败（temperror 时按 RFC 也不该直接判失败，这里如实标注）
        var temperror = dkims.Any(d => d.Outcome == "temperror") || spf.Outcome == "temperror";
        var detail = $"SPF={spf.Outcome}({spf.Domain}) DKIM=[{string.Join(",", dkims.Select(d => $"{d.Outcome}:{d.Domain}"))}] 与 From 域 {fromDomain} 无对齐";
        return new Result(temperror ? "temperror" : "fail", policy, fromDomain, detail);
    }
}

/// <summary>把三件事串起来：SPF → DKIM → DMARC，产出可写进报文的结论与是否判为垃圾。</summary>
public static class InboundAuth
{
    public static async Task<InboundAuthVerdict> CheckAsync(byte[] raw, string clientIp, string helo, string mailFrom,
        AppConfig config, CancellationToken token, IDnsLookup? dns = null)
    {
        dns ??= new UdpDnsLookup(config);
        var cfg = config.InboundAuth;

        var fromDomain = "";
        try
        {
            var parsed = Mime.Parse(raw);
            // 注意：服务端 Mime.Parse 的 From 是**字符串**（不是地址数组），要先用 Mime.Addresses 拆
            fromDomain = Spf.DomainOf(Mime.Addresses(parsed.From).FirstOrDefault() ?? parsed.From);
        }
        catch { /* 报文解析失败就按无 From 处理 */ }

        var spf = await Spf.EvaluateAsync(clientIp, helo, mailFrom, dns, cfg, token);

        var dkimResults = new List<(string Outcome, string Domain)>();
        var dkimDetail = "";
        if (cfg.VerifyDkim)
        {
            var verified = await DkimVerifier.VerifyAllAsync(raw, dns, token);
            foreach (var v in verified) dkimResults.Add((v.Outcome, v.Domain));
            var best = verified.OrderBy(v => v.Outcome == "pass" ? 0 : v.Outcome == "temperror" ? 1 : 2).FirstOrDefault();
            if (best is not null) dkimDetail = $"d={best.Domain} s={best.Selector} {best.Detail}";
        }

        var dmarc = await Dmarc.EvaluateAsync(fromDomain, (spf.Outcome, spf.Domain), dkimResults, dns, token);

        // ── 打分（0 = 干净；阈值默认 3）
        var score = 0;
        var reasons = new List<string>();
        switch (dmarc.Outcome)
        {
            case "fail":
                score += 4;
                reasons.Add($"DMARC 失败（p={dmarc.Policy}）：{dmarc.Detail}");
                if (dmarc.Policy == "reject") score += 2;
                break;
            case "none":
                if (spf.Outcome == "fail") { score += 2; reasons.Add("SPF 硬失败且该域没有 DMARC 记录"); }
                else if (spf.Outcome == "softfail") { score += 1; reasons.Add("SPF 软失败"); }
                else if (spf.Outcome == "permerror") { score += 1; reasons.Add("SPF 记录有错（permerror）"); }
                var anyDkim = dkimResults.Count > 0;
                if (anyDkim && !dkimResults.Any(d => d.Outcome == "pass")) { score += 1; reasons.Add("带了 DKIM 签名但验不过"); }
                break;
        }
        if (spf.Outcome is "none" && dkimResults.Count == 0 && dmarc.Outcome == "none")
            reasons.Add("既没有 SPF 也没有 DKIM（小发件人常见，仅作提示）");

        var hardFail = dmarc.Outcome == "fail" || score >= Math.Max(1, cfg.SpamScoreThreshold);
        var spam = hardFail && cfg.SpamFolderOnFail;
        var reject = dmarc.Outcome == "fail" && dmarc.Policy == "reject" && cfg.RejectOnDmarcReject;

        var verdict = new InboundAuthVerdict
        {
            Spf = spf.Outcome,
            SpfDomain = spf.Domain,
            SpfDetail = spf.Detail,
            Dkim = dkimResults.Count == 0 ? "none"
                : dkimResults.Any(d => d.Outcome == "pass") ? "pass"
                : dkimResults.Any(d => d.Outcome == "temperror") ? "temperror" : "fail",
            DkimDomain = dkimResults.FirstOrDefault().Domain ?? "",
            DkimDetail = dkimDetail,
            Dmarc = dmarc.Outcome,
            DmarcDomain = dmarc.Domain,
            DmarcPolicy = dmarc.Policy,
            Score = score,
            Reasons = reasons.ToArray(),
            Spam = spam,
            Reject = reject,
        };
        return cfg.AddAuthenticationResults ? verdict with { HeaderBlock = BuildHeader(verdict, config) } : verdict;
    }

    private static string BuildHeader(InboundAuthVerdict v, AppConfig config)
    {
        var builder = new StringBuilder();
        builder.Append("Authentication-Results: ").Append(config.Hostname).Append(";\r\n");
        builder.Append("\tspf=").Append(v.Spf);
        if (v.SpfDomain.Length > 0) builder.Append(" smtp.mailfrom=").Append(v.SpfDomain);
        builder.Append(";\r\n");
        builder.Append("\tdkim=").Append(v.Dkim);
        if (v.DkimDomain.Length > 0) builder.Append(" header.d=").Append(v.DkimDomain);
        builder.Append(";\r\n");
        builder.Append("\tdmarc=").Append(v.Dmarc);
        if (v.DmarcDomain.Length > 0) builder.Append(" header.from=").Append(v.DmarcDomain);
        if (v.DmarcPolicy != "none") builder.Append(" policy=").Append(v.DmarcPolicy);
        builder.Append("\r\n");
        builder.Append("X-Spam-Score: ").Append(v.Score).Append("\r\n");
        if (v.Reasons.Length > 0)
            builder.Append("X-Spam-Reason: ").Append(string.Join(" / ", v.Reasons)).Append("\r\n");
        return builder.ToString();
    }

    /// <summary>把校验收到的头前置到报文最前面（不碰原有字节，避免破坏对方 DKIM 签名）。</summary>
    public static byte[] PrependHeaders(byte[] raw, string headerBlock)
    {
        if (string.IsNullOrEmpty(headerBlock)) return raw;
        var prefix = Encoding.Latin1.GetBytes(headerBlock);
        var output = new byte[prefix.Length + raw.Length];
        Buffer.BlockCopy(prefix, 0, output, 0, prefix.Length);
        Buffer.BlockCopy(raw, 0, output, prefix.Length, raw.Length);
        return output;
    }
}
