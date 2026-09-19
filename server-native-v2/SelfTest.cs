using System.Security.Cryptography;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// 自检：不依赖网络与真实邮箱，验证中文编解码、MIME 往返、附件、DKIM 签名可被验证。
/// 用法：WpywMail.Native.exe --selftest
/// </summary>
public static partial class SelfTest
{
    private static int passed;
    private static int failed;

    public static int Run()
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.WriteLine($"=== WpywMail.Native 自检 {BuildInfo.Version} ===");

        var config = new AppConfig
        {
            Domain = "wpy.email",
            Hostname = "mail.example.com",
            AdminEmail = "wpy@wpy.email",
            AdminPassword = "selftest-password-1234",
            DataDirectory = Path.Combine(Path.GetTempPath(), "wpyw-selftest-" + Guid.NewGuid().ToString("N")[..8]),
            Dkim = new DkimConfig { Enabled = true, Selector = "mail" },
        };
        Directory.CreateDirectory(config.DataDirectory);

        try
        {
            TestChineseRoundTrip(config);
            TestMessageIdDomain(config);
            TestRfc2047Decoding();
            TestRawUtf8Headers();
            TestQuotedPrintable();
            TestAttachmentRoundTrip(config);
            TestCharsetFallback();
            TestDkimSignatureVerifies(config);
            TestDkimSurvivesTransport(config);
            TestAddressParsing();
            TestSmtpDataReader();
            TestDkimCanonicalization();
            TestStorageBackends();
            TestAccounts();
            TestInboundAuth();
        }
        catch (Exception ex)
        {
            Fail("自检整体", $"抛出异常：{ex}");
        }
        finally
        {
            try { Directory.Delete(config.DataDirectory, true); } catch { }
        }

        Console.WriteLine();
        Console.WriteLine($"=== 结果：{passed} 项通过，{failed} 项失败 ===");
        return failed == 0 ? 0 : 1;
    }

    // ---------------------------------------------------------------- 用例

    private static void TestChineseRoundTrip(AppConfig config)
    {
        const string subject = "中文主题测试：你好，世界（含全角标点）";
        const string body = "这是正文第一行。\n第二行包含 emoji 之外的符号：→ ★ ①\n第三行结束。";
        var raw = Mime.Build(new ComposeRequest("wpy@wpy.email", "王朋友", ["to@example.com"], [], subject, body), config);
        var parsed = Mime.Parse(raw);

        Check("中文主题往返", parsed.Subject == subject, $"得到「{parsed.Subject}」");
        Check("中文正文往返", parsed.Text == body, $"得到「{parsed.Text.Replace("\n", "\\n")}」");
        Check("正文使用 base64", Encoding.ASCII.GetString(raw).Contains("Content-Transfer-Encoding: base64"), "");
        Check("主题使用 RFC2047", Encoding.ASCII.GetString(raw).Contains("=?UTF-8?B?"), "");
        Check("报文全为 ASCII（可安全传输）", raw.All(b => b < 0x80), "存在 8bit 字节");
        Check("带显示名的中文发件人", RawHeader(raw, "From").Contains("=?UTF-8?B?"), RawHeader(raw, "From"));
    }

    private static void TestMessageIdDomain(AppConfig config)
    {
        var raw = Mime.Build(new ComposeRequest("wpy@wpy.email", null, ["to@example.com"], [], "t", "b"), config);
        var messageId = RawHeader(raw, "Message-ID");
        Check("Message-ID 使用配置域名", messageId.Contains("@wpy.email>"), messageId);
        Check("Message-ID 不再写死旧域名", !messageId.Contains("wpyw.site"), messageId);
    }

    private static void TestRfc2047Decoding()
    {
        var b = "=?UTF-8?B?" + Convert.ToBase64String(Encoding.UTF8.GetBytes("中文主题")) + "?=";
        Check("解码 B 编码字", Mime.DecodeHeader(b) == "中文主题", Mime.DecodeHeader(b));

        var q = "=?UTF-8?Q?=E4=B8=AD=E6=96=87?=";
        Check("解码 Q 编码字", Mime.DecodeHeader(q) == "中文", Mime.DecodeHeader(q));

        var adjacent = "=?UTF-8?B?" + Convert.ToBase64String(Encoding.UTF8.GetBytes("前半")) + "?= =?UTF-8?B?" +
                       Convert.ToBase64String(Encoding.UTF8.GetBytes("后半")) + "?=";
        Check("相邻编码字拼接无多余空格", Mime.DecodeHeader(adjacent) == "前半后半", Mime.DecodeHeader(adjacent));

        var mixed = "Hello " + b;
        Check("编码字与纯文本混排", Mime.DecodeHeader(mixed) == "Hello 中文主题", Mime.DecodeHeader(mixed));
    }

    /// <summary>
    /// 裸 UTF-8 头（没有 RFC 2047 编码字）与 8bit 正文。
    /// 现实中不少客户端这么发；早期版本会把它解成「[æµè¯]」这种乱码。
    /// </summary>
    private static void TestRawUtf8Headers()
    {
        var raw = Encoding.UTF8.GetBytes(
            "From: 张三 <a@example.com>\r\n" +
            "Subject: 中文裸 UTF-8 主题\r\n" +
            "Content-Type: text/plain; charset=UTF-8\r\n" +
            "Content-Transfer-Encoding: 8bit\r\n" +
            "\r\n" +
            "中文正文内容\r\n");
        var parsed = Mime.Parse(raw);
        Check("裸 UTF-8 主题解码", parsed.Subject == "中文裸 UTF-8 主题", parsed.Subject);
        Check("裸 UTF-8 发件人显示名", parsed.From.Contains("张三"), parsed.From);
        Check("8bit 正文解码", parsed.Text == "中文正文内容", parsed.Text);
    }

    private static void TestQuotedPrintable()    {
        var raw = Encoding.ASCII.GetBytes("Subject: =?UTF-8?Q?=E4=B8=AD=E6=96=87?=\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n=E4=B8=AD=E6=96=87=20ok=\r\n=E7=BB=AD=E8=A1=8C\r\n");
        var parsed = Mime.Parse(raw);
        // =E7=BB=AD = U+7EED「续」，且 =CRLF 是软换行必须被合并
        Check("QP 正文解码（含软换行合并）", parsed.Text == "中文 ok续行", $"得到「{parsed.Text}」");
        Check("QP 主题解码", parsed.Subject == "中文", parsed.Subject);
    }

    private static void TestAttachmentRoundTrip(AppConfig config)
    {
        var data = Encoding.UTF8.GetBytes("附件内容：中文测试数据");
        var raw = Mime.Build(new ComposeRequest("wpy@wpy.email", null, ["to@example.com"], [],
            "带附件", "见附件", null, [new OutgoingAttachment("中文报告.txt", "text/plain", data)]), config);
        var parsed = Mime.Parse(raw);

        Check("附件数量", parsed.Attachments.Count == 1, $"{parsed.Attachments.Count}");
        if (parsed.Attachments.Count == 1)
        {
            var attachment = parsed.Attachments[0];
            Check("附件名（中文）", attachment.FileName == "中文报告.txt", attachment.FileName);
            Check("附件内容逐字节一致", attachment.Data.SequenceEqual(data), "");
            Check("附件使用 RFC2231 文件名", Encoding.ASCII.GetString(raw).Contains("filename*=UTF-8''"), "");
        }
        Check("附件存在时正文仍可读", parsed.Text.Contains("见附件"), parsed.Text);
    }

    private static void TestCharsetFallback()
    {
        Check("UTF-8 解码", Mime.DecodeCharset(Encoding.UTF8.GetBytes("中文"), "utf-8") == "中文", "");
        Check("未知字符集回退不崩", Mime.DecodeCharset(Encoding.UTF8.GetBytes("中文"), "x-unknown-999") == "中文", "");

        var provider = CodePagesShim.Provider;
        if (provider is not null)
        {
            try
            {
                Encoding.RegisterProvider(provider);
                var gbk = Encoding.GetEncoding(936).GetBytes("中文测试");
                Check("GBK 解码", Mime.DecodeCharset(gbk, "gb2312") == "中文测试", Mime.DecodeCharset(gbk, "gb2312"));
            }
            catch (Exception ex) { Check("GBK 解码", false, ex.Message); }
        }
        else
        {
            Console.WriteLine("  [跳过] GBK 解码（未引用 System.Text.Encoding.CodePages）");
        }
    }

    private static void TestDkimSignatureVerifies(AppConfig config)
    {
        var signer = DkimSigner.Create(config);
        if (signer is null) { Check("DKIM 初始化", false, "返回 null"); return; }

        var raw = Mime.Build(new ComposeRequest("wpy@wpy.email", null, ["to@example.com"], [],
            "DKIM 测试主题", "DKIM 测试正文内容。"), config);
        var signed = signer.Sign(raw);

        Check("报文已带 DKIM-Signature", Encoding.ASCII.GetString(signed).Contains("DKIM-Signature:"), "");
        Check("被签名报文仍是 ASCII", signed.All(b => b < 0x80), "");
        Check("DKIM 签名可被本地验证（RFC 6376 §3.7 顺序）", VerifyDkim(signed, signer), "签名校验失败");
        // 反向对照：如果验签器把「签名头放最前 + 结尾带 CRLF」也判为有效，说明它根本没在
        // 按 RFC 校验（2026-09-13 的真实事故就是签名端与验签端一起犯错导致假通过）。
        Check("（反向对照）非规范顺序必须验不过",
            !VerifyDkim(signed, signer, rfcOrder: false), "两种顺序都能通过 → 验签器未按 RFC 6376 校验");
    }

    /// <summary>
    /// 最关键的一致性测试：签名覆盖的字节必须与传输写出的字节完全一致。
    /// 用一个「裸 LF 行尾 + 以点开头的行」的恶劣报文走完整链路：
    /// 规范化 → 签名 → DATA 编码（dot-stuffing）→ 收件端还原 → 验签。
    /// 若签名后才改行尾，或 dot-stuffing 破坏了正文，这里必然失败。
    /// </summary>
    private static void TestDkimSurvivesTransport(AppConfig config)
    {
        var signer = DkimSigner.Create(config);
        if (signer is null) { Check("DKIM 传输一致性", false, "签名器不可用"); return; }

        var hostile = Encoding.UTF8.GetBytes(
            "From: wpy@wpy.email\n" +
            "To: to@example.com\n" +
            "Subject: 传输一致性测试\n" +
            "MIME-Version: 1.0\n" +
            "Content-Type: text/plain; charset=UTF-8\n" +
            "Content-Transfer-Encoding: 8bit\n" +
            "\n" +
            "第一行中文\n" +
            ". 这一行以点开头\n" +
            "最后一行\n");

        var normalized = SmtpDataEncoder.Normalize(hostile);
        // 注意：报文是 UTF-8 字节，检查时必须按 UTF-8 还原（用 Latin-1 解会得到乱码而匹配不上）
        Check("裸 LF 在签名前被规范化为 CRLF",
            Encoding.UTF8.GetString(normalized).Contains("\r\n. 这一行以点开头\r\n"),
            "");

        var signed = signer.Sign(normalized);
        var wire = SmtpDataEncoder.Encode(signed);
        Check("线上报文对行首点做了 dot-stuffing",
            Encoding.UTF8.GetString(wire).Contains("\r\n.. 这一行以点开头\r\n"),
            "");

        var received = SmtpDataEncoder.Decode(wire);
        Check("接收端还原后与签名前字节一致", received.SequenceEqual(signed), "");

        var verified = VerifyDkim(received, signer);
        Check("DKIM 经过完整传输变换后仍可验证", verified, "签名校验失败");
    }

    private static void TestAddressParsing()
    {
        var result = Mime.Addresses("张三 <a@example.com>, b@example.com; \"李四, 五\" <c@example.com>");
        Check("地址解析（含引号内逗号）", result.Length == 3 && result[0] == "a@example.com" && result[2] == "c@example.com",
            string.Join(" | ", result));
        Check("非法地址被过滤", Mime.Addresses("not-an-address, ok@example.com").Length == 1, "");
    }

    private static void TestSmtpDataReader()
    {
        // 模拟客户端发送：正文里有中文 UTF-8、以点开头的行需要 dot-stuffing
        var payload = "Subject: 测试\r\n\r\n.. 以点开头\r\n中文内容\r\n";
        var wire = Encoding.UTF8.GetBytes(payload.Replace("\r\n", "\r\n"));
        using var stream = new MemoryStream();
        // 客户端在 DATA 后追加结束行
        stream.Write(wire);
        stream.Write(Encoding.ASCII.GetBytes(".\r\n"));
        stream.Position = 0;

        var reader = new SmtpReader(stream);
        var data = reader.ReadDataAsync(1024 * 1024, CancellationToken.None).GetAwaiter().GetResult();
        var text = Encoding.UTF8.GetString(data);

        Check("DATA 读取保留 UTF-8 中文", text.Contains("中文内容"), text.Replace("\r\n", "\\n"));
        Check("DATA 读取做 dot-unstuffing", text.Contains(". 以点开头"), text.Replace("\r\n", "\\n"));
        Check("DATA 读取行尾统一 CRLF", text.EndsWith("\r\n"), "");
    }

    private static void TestDkimCanonicalization()
    {
        // 折行 + 多余空白应被规范化成单空格
        var raw = Encoding.ASCII.GetBytes("From: a@b.com\r\nSubject:  hello   world \r\n\tcontinued\r\n\r\nbody\r\n");
        var (headers, _) = SplitForTest(raw);
        var subject = headers.First(h => h.Name == "Subject");
        var canonical = CanonicalForTest(subject.Name, subject.Value);
        Check("relaxed 头规范化（折行与空白）", canonical == "subject:hello world continued", canonical);
    }

    // ---------------------------------------------------------------- DKIM 校验（独立于签名器的实现）

    /// <summary>
    /// 按 RFC 6376 §3.7 第 2 步重建签名输入并验签。
    /// rfcOrder=false 时故意用「DKIM-Signature 放最前 + 结尾带 CRLF」的**非规范**顺序，
    /// 仅用于反向对照：非规范顺序绝不能被判为有效。
    /// </summary>
    private static bool VerifyDkim(byte[] message, DkimSigner signer, bool rfcOrder = true)
    {
        var (headers, body) = SplitForTest(message);
        var dkim = headers.FirstOrDefault(h => h.Name.Equals("DKIM-Signature", StringComparison.OrdinalIgnoreCase));
        if (dkim.Name is null) return false;

        var tags = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in dkim.Value.Split(';'))
        {
            var equals = part.IndexOf('=');
            if (equals > 0) tags[part[..equals].Trim()] = part[(equals + 1)..].Trim();
        }
        if (!tags.TryGetValue("b", out var signatureBase64) || !tags.TryGetValue("bh", out var bodyHash)) return false;
        if (!tags.TryGetValue("h", out var headerList)) return false;

        // 1) 正文哈希
        var canonicalBody = CanonicalBodyForTest(body);
        var computedBodyHash = Convert.ToBase64String(SHA256.HashData(canonicalBody));
        if (computedBodyHash != bodyHash.Trim()) return false;

        // 2) 重建签名输入
        var withoutSignature = dkim.Value.Replace(tags["b"], "").TrimEnd();
        var signatureLine = CanonicalForTest("DKIM-Signature", withoutSignature);
        var builder = new StringBuilder();

        if (!rfcOrder)
        {
            builder.Append(signatureLine).Append("\r\n");
        }

        foreach (var name in headerList.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            var header = headers.FirstOrDefault(h => h.Name.Equals(name.Trim(), StringComparison.OrdinalIgnoreCase));
            if (header == default) return false;
            builder.Append(CanonicalForTest(header.Name, header.Value)).Append("\r\n");
        }

        if (rfcOrder)
        {
            // RFC 6376 §3.7：签名头放最后，且不带结尾 CRLF
            builder.Append(signatureLine);
        }

        var publicKey = RSA.Create();
        publicKey.ImportSubjectPublicKeyInfo(signer.PublicKeyBytes, out _);
        // 与签名端一致用 Latin1（字节保真）：ASCII 会把 8bit 头里的非 ASCII 字符替换成 '?'
        return publicKey.VerifyData(Encoding.Latin1.GetBytes(builder.ToString()),
            Convert.FromBase64String(signatureBase64), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static byte[] CanonicalBodyForTest(byte[] body)
    {
        var text = Encoding.Latin1.GetString(body).Replace("\r\n", "\n").Replace('\r', '\n');
        var lines = text.Split('\n').Select(l => CollapseForTest(l).TrimEnd(' ', '\t'));
        var joined = string.Join("\r\n", lines).TrimEnd('\r', '\n');
        if (joined.Length > 0) joined += "\r\n";
        return Encoding.Latin1.GetBytes(joined);
    }

    private static string CanonicalForTest(string name, string value)
    {
        var unfolded = value.Replace("\r\n", "").Replace("\n", "");
        return name.Trim().ToLowerInvariant() + ":" + CollapseForTest(unfolded).Trim();
    }

    private static string CollapseForTest(string value)
    {
        var builder = new StringBuilder();
        var inWhitespace = false;
        foreach (var c in value)
        {
            if (c is ' ' or '\t') { if (!inWhitespace) builder.Append(' '); inWhitespace = true; }
            else { builder.Append(c); inWhitespace = false; }
        }
        return builder.ToString();
    }

    private static (List<(string Name, string Value)> Headers, byte[] Body) SplitForTest(byte[] message)
    {
        var headers = new List<(string, string)>();
        var index = 0;
        string? name = null;
        var value = new StringBuilder();
        while (index < message.Length)
        {
            var lineEnd = Array.IndexOf(message, (byte)'\n', index);
            if (lineEnd < 0) lineEnd = message.Length;
            var line = Encoding.Latin1.GetString(message, index, lineEnd - index).TrimEnd('\r');
            index = lineEnd + 1;
            if (line.Length == 0) break;
            if ((line[0] == ' ' || line[0] == '\t') && name is not null) { value.Append("\r\n").Append(line); continue; }
            if (name is not null) headers.Add((name, value.ToString()));
            var colon = line.IndexOf(':');
            if (colon <= 0) { name = null; value.Clear(); continue; }
            name = line[..colon].Trim();
            value.Clear().Append(line[(colon + 1)..]);
        }
        if (name is not null) headers.Add((name, value.ToString()));
        return (headers, message[Math.Min(index, message.Length)..]);
    }

    private static string RawHeader(byte[] raw, string name)
    {
        var (headers, _) = SplitForTest(raw);
        var header = headers.FirstOrDefault(h => h.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
        return header == default ? "" : header.Value.Trim();
    }

    // ---------------------------------------------------------------- 断言

    private static void Check(string title, bool ok, string detail)
    {
        if (ok)
        {
            passed++;
            Console.WriteLine($"  [通过] {title}");
        }
        else
        {
            failed++;
            Console.WriteLine($"  [失败] {title}" + (string.IsNullOrEmpty(detail) ? "" : $" —— {detail}"));
        }
    }

    private static void Fail(string title, string detail) => Check(title, false, detail);
}
