using System.Security.Cryptography;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// DKIM 签名（RFC 6376），算法 rsa-sha256，规范化 relaxed/relaxed。
///
/// 私钥不存在时会自动生成 2048 位 RSA 并保存为 PEM，同时把需要配置到 DNS 的
/// TXT 记录打印到日志，方便直接复制到 Cloudflare。
/// </summary>
public sealed class DkimSigner
{
    private const string Crlf = "\r\n";

    private readonly RSA key;
    private readonly string domain;
    private readonly string selector;
    private readonly string[] signHeaders;

    public string PrivateKeyPath { get; }

    /// <summary>SubjectPublicKeyInfo 形式的公钥（自检与 DNS 记录生成使用）。</summary>
    public byte[] PublicKeyBytes => key.ExportSubjectPublicKeyInfo();

    /// <summary>DKIM 公钥所在的 DNS 记录名（不含域后缀）。</summary>
    public string RecordName => $"{selector}._domainkey";

    /// <summary>DKIM 公钥记录值（TXT）。</summary>
    public string RecordValue => "v=DKIM1; k=rsa; p=" + Convert.ToBase64String(PublicKeyBytes);

    private DkimSigner(RSA key, string domain, string selector, string privateKeyPath, string[] headers)
    {
        this.key = key;
        this.domain = domain;
        this.selector = selector;
        PrivateKeyPath = privateKeyPath;
        signHeaders = headers;
    }

    /// <summary>按配置创建签名器；未启用或初始化失败时返回 null（调用方继续正常发信）。</summary>
    public static DkimSigner? Create(AppConfig config)
    {
        if (!config.Dkim.Enabled) return null;
        try
        {
            var domain = string.IsNullOrWhiteSpace(config.Dkim.SigningDomain) ? config.Domain : config.Dkim.SigningDomain;
            var selector = string.IsNullOrWhiteSpace(config.Dkim.Selector) ? "mail" : config.Dkim.Selector.Trim();
            var path = config.Dkim.PrivateKeyPath;
            if (string.IsNullOrWhiteSpace(path)) path = Path.Combine(config.DataDirectory, "dkim", selector + ".private.pem");

            Directory.CreateDirectory(Path.GetDirectoryName(path)!);

            RSA rsa;
            if (File.Exists(path))
            {
                rsa = RSA.Create();
                rsa.ImportFromPem(File.ReadAllText(path));
                AppLog.Info($"[DKIM] 已加载私钥：{path}（{rsa.KeySize} 位，选择器 {selector}，域 {domain}）");
            }
            else
            {
                rsa = RSA.Create(2048);
                File.WriteAllText(path, rsa.ExportPkcs8PrivateKeyPem(), new UTF8Encoding(false));
                AppLog.Info($"[DKIM] 已生成新的 2048 位私钥：{path}");
            }

            var signer = new DkimSigner(rsa, domain, selector, path, config.Dkim.Headers);
            signer.PrintDnsRecord();
            return signer;
        }
        catch (Exception ex)
        {
            AppLog.Error($"[DKIM] 初始化失败，将不签名继续发信：{ex.Message}");
            return null;
        }
    }

    /// <summary>把需要配置到 DNS 的公钥记录打印出来（分段给 TXT 用）。</summary>
    public void PrintDnsRecord()
    {
        var publicKey = Convert.ToBase64String(key.ExportSubjectPublicKeyInfo());
        var name = $"{selector}._domainkey.{domain}";
        var value = "v=DKIM1; k=rsa; p=" + publicKey;
        AppLog.Info($"[DKIM] 请在 DNS 添加 TXT 记录 —— 名称：{name}");
        AppLog.Info($"[DKIM] 值（TXT，可直接整条粘贴）：{value}");
        foreach (var chunk in Chunk(value, 255))
        {
            AppLog.Info($"[DKIM]   （分段）\"{chunk}\"");
        }
    }

    public static IEnumerable<string> Chunk(string value, int size)
    {
        for (var index = 0; index < value.Length; index += size)
        {
            yield return value.Substring(index, Math.Min(size, value.Length - index));
        }
    }

    /// <summary>对整封邮件签名，返回带 DKIM-Signature 头的新报文。失败时原样返回。</summary>
    public byte[] Sign(byte[] message)
    {
        try
        {
            var (rawHeaders, body) = SplitRaw(message);
            if (rawHeaders.Count == 0) return message;
            if (!rawHeaders.Any(h => h.Name.Equals("From", StringComparison.OrdinalIgnoreCase)))
            {
                AppLog.Warn("[DKIM] 报文缺少 From 头，跳过签名。");
                return message;
            }

            var bodyHash = Convert.ToBase64String(SHA256.HashData(CanonicalizeBody(body)));

            // 按配置顺序挑出实际存在的头（每个名字只签第一次出现）
            var chosen = new List<(string Name, string Value)>();
            foreach (var name in signHeaders)
            {
                var hit = rawHeaders.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                if (hit.Name is not null && !chosen.Any(c => c.Name.Equals(hit.Name, StringComparison.OrdinalIgnoreCase)))
                    chosen.Add(hit);
            }
            if (!chosen.Any(c => c.Name.Equals("From", StringComparison.OrdinalIgnoreCase)))
                chosen.Insert(0, rawHeaders.First(h => h.Name.Equals("From", StringComparison.OrdinalIgnoreCase)));

            var headerList = string.Join(":", chosen.Select(c => c.Name.ToLowerInvariant()));
            var baseValue = $"v=1; a=rsa-sha256; c=relaxed/relaxed; d={domain}; s={selector}; " +
                            $"t={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}; h={headerList}; bh={bodyHash}; b=";

            // RFC 6376 §3.7「hash step 2」规定的顺序，必须严格照做：
            //   1. 先按 h= 标签里的顺序哈希各被签名头，**每个头后面跟一个 CRLF**；
            //   2. **最后**才哈希 DKIM-Signature 头本身（b= 视为空串），且它**结尾不带 CRLF**。
            // 把 DKIM-Signature 放在最前面、或给它补一个结尾 CRLF，都会让合规的验证器
            // （Gmail / Outlook / OpenDKIM / Mail::DKIM / dkimpy）算出不同的摘要 ——
            // 表现为对方直接判 dkim=fail，而自家自测却可能因为「签名端与验签端犯同一个错」
            // 而假通过。2026-09-13 的真实教训：port25 的验证器就是这样把这个 bug 揪出来的。
            var signingInput = new StringBuilder();
            foreach (var (name, value) in chosen)
            {
                signingInput.Append(CanonicalizeHeader(name, value)).Append(Crlf);
            }
            signingInput.Append(CanonicalizeHeader("DKIM-Signature", baseValue));

            // ⚠ 必须用 Latin1（字节保真）取输入字节，**不能用 ASCII**：
            //   ASCII 编码会把非 ASCII 字符替换成 '?'，如果报文头是 8bit 裸 UTF-8（不是 RFC2047
            //   编码字），签名输入就与实际字节不一致 → 对方验签失败。
            //   我们自己发出的信因为头都经过 RFC2047 编码，所以一直是 ASCII（这条缺陷因此潜伏着），
            //   但验签端按真实字节算，一旦遇到 8bit 头就会对不上。自检的 DKIM 用例把它逼了出来。
            var signature = key.SignData(Encoding.Latin1.GetBytes(signingInput.ToString()),
                HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            var signatureHeader = $"DKIM-Signature: {baseValue}{Convert.ToBase64String(signature)}{Crlf}";
            var output = new MemoryStream(message.Length + signatureHeader.Length + 64);
            output.Write(Encoding.ASCII.GetBytes(signatureHeader));
            output.Write(message);
            return output.ToArray();
        }
        catch (Exception ex)
        {
            AppLog.Error($"[DKIM] 签名失败，将发送未签名报文：{ex.Message}");
            return message;
        }
    }

    // ---------------------------------------------------------------- 规范化

    /// <summary>relaxed 头规范化：小写名、展开折行、多空白折成一个空格、去首尾空白。</summary>
    private static string CanonicalizeHeader(string name, string value)
    {
        var unfolded = value.Replace("\r\n", "").Replace("\n", "");
        var collapsed = CollapseWhitespace(unfolded).Trim();
        return name.Trim().ToLowerInvariant() + ":" + collapsed;
    }

    /// <summary>relaxed 正文规范化：多空白折成一个空格、去行尾空白、去掉末尾空行。</summary>
    private static byte[] CanonicalizeBody(byte[] body)
    {
        var text = Encoding.Latin1.GetString(body).Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = text.Split('\n');
        var normalized = lines.Select(line => CollapseWhitespace(line).TrimEnd(' ', '\t'));
        var joined = string.Join(Crlf, normalized);
        joined = joined.TrimEnd('\r', '\n');
        if (joined.Length > 0) joined += Crlf;
        return Encoding.Latin1.GetBytes(joined);
    }

    private static string CollapseWhitespace(string value)
    {
        var builder = new StringBuilder(value.Length);
        var inWhitespace = false;
        foreach (var c in value)
        {
            if (c is ' ' or '\t')
            {
                if (!inWhitespace) builder.Append(' ');
                inWhitespace = true;
            }
            else
            {
                builder.Append(c);
                inWhitespace = false;
            }
        }
        return builder.ToString();
    }

    /// <summary>把报文拆成「原始头行（未展开）」与「正文字节」，保持字节忠实。</summary>
    private static (List<(string Name, string Value)> Headers, byte[] Body) SplitRaw(byte[] message)
    {
        var headers = new List<(string, string)>();
        var index = 0;
        string? currentName = null;
        var currentValue = new StringBuilder();

        while (index < message.Length)
        {
            var lineEnd = Array.IndexOf(message, (byte)'\n', index);
            if (lineEnd < 0) lineEnd = message.Length;
            var line = Encoding.Latin1.GetString(message, index, lineEnd - index).TrimEnd('\r');
            index = lineEnd + 1;

            if (line.Length == 0) break; // 头结束
            if ((line[0] == ' ' || line[0] == '\t') && currentName is not null)
            {
                currentValue.Append(Crlf).Append(line);
                continue;
            }

            if (currentName is not null) headers.Add((currentName, currentValue.ToString()));
            var colon = line.IndexOf(':');
            if (colon <= 0) { currentName = null; currentValue.Clear(); continue; }
            currentName = line[..colon].Trim();
            currentValue.Clear();
            currentValue.Append(line[(colon + 1)..]);
        }
        if (currentName is not null) headers.Add((currentName, currentValue.ToString()));

        var bodyStart = Math.Min(index, message.Length);
        return (headers, message[bodyStart..]);
    }
}
