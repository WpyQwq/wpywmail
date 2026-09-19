using System.Globalization;
using System.Text;

namespace WpywMail.Native;

/// <summary>一个解析出来的附件。</summary>
public sealed record ParsedAttachment(string FileName, string ContentType, byte[] Data, string ContentId, bool Inline);

/// <summary>解析结果。Text / Html 已经解码成可直接展示的字符串。</summary>
public sealed record ParsedMime(
    string From,
    string To,
    string Cc,
    string Subject,
    string MessageId,
    string InReplyTo,
    string References,
    DateTimeOffset? Date,
    string Text,
    string Html,
    IReadOnlyList<ParsedAttachment> Attachments);

/// <summary>待发送的附件。</summary>
public sealed record OutgoingAttachment(string FileName, string ContentType, byte[] Data, string ContentId = "", bool Inline = false);

/// <summary>组装一封待发送邮件的入参。</summary>
public sealed record ComposeRequest(
    string From,
    string? FromDisplay,
    string[] To,
    string[] Cc,
    string Subject,
    string Text,
    string? Html = null,
    IReadOnlyList<OutgoingAttachment>? Attachments = null,
    string? MessageId = null,
    string InReplyTo = "",
    string References = "");

/// <summary>
/// MIME 组装与解析。
///
/// 相比 v1 的关键修正：
///  1. 组装：Message-ID 的域来自配置（不再写死），正文与附件一律 base64，
///     非 ASCII 头一律 RFC 2047 编码并按 75 字符上限切分。
///  2. 解析：正确解码 RFC 2047 编码字、Content-Transfer-Encoding（base64/QP）、
///     charset（含 GBK/GB18030），并支持 multipart 与附件。
/// </summary>
public static class Mime
{
    private const string Crlf = "\r\n";

    // ---------------------------------------------------------------- 解析

    public static ParsedMime Parse(byte[] raw)
    {
        var (headers, body) = SplitMessage(raw);
        return ParseEntity(headers, body);
    }

    private static ParsedMime ParseEntity(List<KeyValuePair<string, string>> headers, byte[] body)
    {
        string Header(string name) => headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value ?? "";

        var from = AddressText(DecodeHeader(Header("From")));
        var to = AddressText(DecodeHeader(Header("To")));
        var cc = AddressText(DecodeHeader(Header("Cc")));
        var subject = DecodeHeader(Header("Subject"));
        if (string.IsNullOrWhiteSpace(subject)) subject = "(无主题)";

        var contentType = Header("Content-Type");
        var (mediaType, parameters) = ParseContentType(contentType);
        var transferEncoding = Header("Content-Transfer-Encoding").Trim().ToLowerInvariant();

        var text = new StringBuilder();
        var html = new StringBuilder();
        var attachments = new List<ParsedAttachment>();

        if (mediaType.StartsWith("multipart/", StringComparison.OrdinalIgnoreCase) &&
            parameters.TryGetValue("boundary", out var boundary) && !string.IsNullOrEmpty(boundary))
        {
            foreach (var part in SplitMultipart(body, boundary))
            {
                var (partHeaders, partBody) = SplitMessage(part);
                var nested = ParseEntity(partHeaders, partBody);
                // 嵌套的多部分（例如 mixed 里套 alternative）
                if (nested.Text.Length > 0) text.Append(nested.Text);
                if (nested.Html.Length > 0) html.Append(nested.Html);
                attachments.AddRange(nested.Attachments);
            }
        }
        else
        {
            var decoded = DecodeTransfer(body, transferEncoding);
            var charset = parameters.TryGetValue("charset", out var cs) ? cs : null;
            var content = DecodeCharset(decoded, charset);

            var isAttachment = parameters.TryGetValue("name", out var name) && !string.IsNullOrWhiteSpace(name);
            var disposition = Header("Content-Disposition");
            var (dispType, dispParams) = ParseContentType(disposition);
            if (dispType.Equals("attachment", StringComparison.OrdinalIgnoreCase) ||
                (dispType.Equals("inline", StringComparison.OrdinalIgnoreCase) && !mediaType.StartsWith("text/", StringComparison.OrdinalIgnoreCase)))
                isAttachment = true;

            if (isAttachment)
            {
                var fileName = DecodeParameter(dispParams.GetValueOrDefault("filename*"))
                               ?? DecodeHeader(dispParams.GetValueOrDefault("filename") ?? "")
                               ?? DecodeParameter(parameters.GetValueOrDefault("name*"))
                               ?? DecodeHeader(parameters.GetValueOrDefault("name") ?? "")
                               ?? "attachment.bin";
                if (string.IsNullOrWhiteSpace(fileName)) fileName = "attachment.bin";
                attachments.Add(new ParsedAttachment(
                    fileName,
                    mediaType,
                    decoded,
                    Header("Content-ID").Trim('<', '>'),
                    dispType.Equals("inline", StringComparison.OrdinalIgnoreCase)));
            }
            else if (mediaType.Equals("text/html", StringComparison.OrdinalIgnoreCase))
            {
                html.Append(content);
            }
            else
            {
                text.Append(content);
            }
        }

        return new ParsedMime(
            from, to, cc, subject,
            Header("Message-ID").Trim(),
            Header("In-Reply-To").Trim(),
            Header("References").Trim(),
            ParseDate(Header("Date")),
            text.ToString().TrimEnd(),
            html.ToString().TrimEnd(),
            attachments);
    }

    private static DateTimeOffset? ParseDate(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        if (DateTimeOffset.TryParse(value.Trim(), CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var parsed)) return parsed;
        // 常见变体：缺秒、单数字日等
        var cleaned = value.Replace("GMT", "+0000").Replace("UT", "+0000").Trim();
        if (DateTimeOffset.TryParse(cleaned, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out parsed)) return parsed;
        return null;
    }

    /// <summary>把原始字节切成「头（已展开）」与「正文」。</summary>
    internal static (List<KeyValuePair<string, string>> Headers, byte[] Body) SplitMessage(byte[] raw)
    {
        var separator = IndexOf(raw, Crlf + Crlf);
        var separatorLength = 4;
        if (separator < 0)
        {
            separator = IndexOf(raw, "\n\n");
            separatorLength = 2;
        }

        var headerBytes = separator >= 0 ? raw[..separator] : raw;
        var body = separator >= 0 ? raw[(separator + separatorLength)..] : [];
        var headerText = DecodeHeaderBlock(headerBytes);

        var headers = new List<KeyValuePair<string, string>>();
        string? currentName = null;
        var currentValue = new StringBuilder();
        void Flush()
        {
            if (currentName is not null) headers.Add(new KeyValuePair<string, string>(currentName, currentValue.ToString().Trim()));
            currentName = null;
            currentValue.Clear();
        }

        foreach (var line in headerText.Split('\n'))
        {
            if (line.Length == 0) continue;
            if ((line[0] == ' ' || line[0] == '\t') && currentName is not null)
            {
                currentValue.Append(' ').Append(line.Trim());
                continue;
            }
            Flush();
            var colon = line.IndexOf(':');
            if (colon <= 0) continue;
            currentName = line[..colon].Trim();
            currentValue.Append(line[(colon + 1)..].Trim());
        }
        Flush();
        return (headers, body);
    }

    /// <summary>
    /// 解码头部块。
    ///
    /// 头部按标准应当是 ASCII（非 ASCII 必须用 RFC 2047 编码字），但现实中不少客户端
    /// 直接把裸 UTF-8 写进头里（8bit 头）。这里优先按 UTF-8 严格解码，失败再回退
    /// Latin-1（保证字节不丢）；否则裸 UTF-8 的中文主题会变成 «æµè¯» 这种乱码。
    /// </summary>
    private static string DecodeHeaderBlock(byte[] bytes)
    {
        try
        {
            return new UTF8Encoding(false, throwOnInvalidBytes: true).GetString(bytes).Replace("\r\n", "\n").Replace('\r', '\n');
        }
        catch (DecoderFallbackException)
        {
            return Encoding.Latin1.GetString(bytes).Replace("\r\n", "\n").Replace('\r', '\n');
        }
    }

    /// <summary>按 boundary 切分 multipart 正文。返回每个子部分的原始字节。</summary>
    private static List<byte[]> SplitMultipart(byte[] body, string boundary)
    {
        var parts = new List<byte[]>();
        var delimiter = Encoding.ASCII.GetBytes("--" + boundary);
        var positions = new List<int>();
        for (var i = 0; i + delimiter.Length <= body.Length; i++)
        {
            if (body[i] != (byte)'-') continue;
            var match = true;
            for (var j = 0; j < delimiter.Length; j++)
            {
                if (body[i + j] != delimiter[j]) { match = false; break; }
            }
            if (match) { positions.Add(i); i += delimiter.Length - 1; }
        }
        if (positions.Count < 2) return parts;

        for (var index = 0; index < positions.Count - 1; index++)
        {
            var start = positions[index];
            // 跳过边界行自身
            var lineEnd = IndexOf(body, start, "\n");
            if (lineEnd < 0) continue;
            start = lineEnd + 1;
            var end = positions[index + 1];
            // 去掉结尾的 CRLF
            while (end > start && (body[end - 1] == (byte)'\n' || body[end - 1] == (byte)'\r')) end--;
            if (end > start) parts.Add(body[start..end]);
        }
        return parts;
    }

    /// <summary>解码 Content-Transfer-Encoding。</summary>
    private static byte[] DecodeTransfer(byte[] body, string encoding) => encoding switch
    {
        "base64" => TryBase64(body),
        "quoted-printable" => DecodeQuotedPrintable(body),
        _ => body, // 7bit / 8bit / binary / 空
    };

    private static byte[] TryBase64(byte[] body)
    {
        // 去掉所有空白字符后解码；容错处理不完整的 base64
        var buffer = new StringBuilder(body.Length);
        foreach (var b in body)
        {
            if (b is (byte)' ' or (byte)'\r' or (byte)'\n' or (byte)'\t') continue;
            if (b == (byte)'=') { buffer.Append('='); continue; }
            buffer.Append((char)b);
        }
        var text = buffer.ToString();
        var padding = text.Length % 4;
        if (padding == 1) text = text[..^1];
        else if (padding is 2 or 3) text += new string('=', 4 - padding);
        try { return Convert.FromBase64String(text); }
        catch (FormatException) { return []; }
    }

    private static byte[] DecodeQuotedPrintable(byte[] body)
    {
        using var output = new MemoryStream(body.Length);
        for (var i = 0; i < body.Length; i++)
        {
            var b = body[i];
            if (b != (byte)'=') { output.WriteByte(b); continue; }

            // 软换行 =CRLF / =LF
            if (i + 1 < body.Length && body[i + 1] == (byte)'\n') { i += 1; continue; }
            if (i + 2 < body.Length && body[i + 1] == (byte)'\r' && body[i + 2] == (byte)'\n') { i += 2; continue; }
            if (i + 2 < body.Length && IsHex(body[i + 1]) && IsHex(body[i + 2]))
            {
                output.WriteByte((byte)((HexValue(body[i + 1]) << 4) | HexValue(body[i + 2])));
                i += 2;
                continue;
            }
            output.WriteByte(b);
        }
        return output.ToArray();

        static bool IsHex(byte b) => (b >= '0' && b <= '9') || (b >= 'A' && b <= 'F') || (b >= 'a' && b <= 'f');
        static int HexValue(byte b) => b switch
        {
            >= (byte)'0' and <= (byte)'9' => b - '0',
            >= (byte)'A' and <= (byte)'F' => b - 'A' + 10,
            _ => b - 'a' + 10,
        };
    }

    // ---------------------------------------------------------------- 头编码

    /// <summary>解码 RFC 2047 编码字；相邻编码字之间的空白会被丢弃。</summary>
    public static string DecodeHeader(string value)
    {
        if (string.IsNullOrEmpty(value) || !value.Contains("=?")) return value ?? "";

        var result = new StringBuilder();
        var index = 0;
        var lastWasEncoded = false;
        while (index < value.Length)
        {
            var start = value.IndexOf("=?", index, StringComparison.Ordinal);
            if (start < 0) { result.Append(value, index, value.Length - index); break; }

            // 编码字之间的空格应被忽略
            var gap = value[index..start];
            if (!(lastWasEncoded && gap.Trim().Length == 0)) result.Append(gap);
            else if (lastWasEncoded) { /* 丢弃 */ }

            var firstQuestion = value.IndexOf('?', start + 2);
            var secondQuestion = firstQuestion < 0 ? -1 : value.IndexOf('?', firstQuestion + 1);
            var end = secondQuestion < 0 ? -1 : value.IndexOf("?=", secondQuestion + 1, StringComparison.Ordinal);
            if (firstQuestion < 0 || secondQuestion < 0 || end < 0)
            {
                result.Append(value, start, value.Length - start);
                break;
            }

            var charset = value[(start + 2)..firstQuestion];
            var encoding = value[(firstQuestion + 1)..secondQuestion];
            var payload = value[(secondQuestion + 1)..end];
            try
            {
                byte[] bytes;
                if (encoding.Equals("B", StringComparison.OrdinalIgnoreCase))
                    bytes = Convert.FromBase64String(payload);
                else if (encoding.Equals("Q", StringComparison.OrdinalIgnoreCase))
                    bytes = DecodeQ(payload);
                else { result.Append(value, start, end + 2 - start); index = end + 2; lastWasEncoded = false; continue; }

                result.Append(DecodeCharset(bytes, charset));
                lastWasEncoded = true;
            }
            catch
            {
                result.Append(value, start, end + 2 - start);
                lastWasEncoded = false;
            }
            index = end + 2;
        }
        return result.ToString();

        static byte[] DecodeQ(string payload)
        {
            using var output = new MemoryStream();
            for (var i = 0; i < payload.Length; i++)
            {
                var c = payload[i];
                if (c == '_') { output.WriteByte((byte)' '); continue; }
                if (c == '=' && i + 2 < payload.Length)
                {
                    try { output.WriteByte(Convert.ToByte(payload.Substring(i + 1, 2), 16)); i += 2; continue; }
                    catch { }
                }
                output.WriteByte((byte)c);
            }
            return output.ToArray();
        }
    }

    /// <summary>解码 RFC 2231 参数值（形如 UTF-8''%E4%B8%AD%文）。</summary>
    private static string? DecodeParameter(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return null;
        var text = value.Trim();
        var separator = text.IndexOf("''", StringComparison.Ordinal);
        if (separator < 0) return null;
        var charset = text[..separator];
        var encoded = text[(separator + 2)..];
        try
        {
            using var buffer = new MemoryStream(encoded.Length);
            for (var i = 0; i < encoded.Length; i++)
            {
                if (encoded[i] == '%' && i + 2 < encoded.Length)
                {
                    buffer.WriteByte(Convert.ToByte(encoded.Substring(i + 1, 2), 16));
                    i += 2;
                }
                else buffer.WriteByte((byte)encoded[i]);
            }
            return DecodeCharset(buffer.ToArray(), charset);
        }
        catch { return null; }
    }

    /// <summary>对外暴露的 RFC 2047 编码入口（IMAP ENVELOPE 等需要把非 ASCII 头值变成 ASCII）。</summary>
    public static string EncodeHeaderValue(string value) =>
        EncodeHeader(value ?? "").Replace("\r\n", " ").Replace("\n", " ");

    /// <summary>需要时把文本编码成 RFC 2047 编码字（按 75 字符上限切分）。</summary>
    private static string EncodeHeader(string value)
    {
        if (string.IsNullOrEmpty(value)) return "";
        if (value.All(c => c is >= ' ' and <= '~')) return value;

        var bytes = Encoding.UTF8.GetBytes(value);
        var chunks = new List<string>();
        var offset = 0;
        while (offset < bytes.Length)
        {
            // 每个编码字最多 75 字符；"=?UTF-8?B?" + "?=" 占 12 个字符 → base64 最多 63
            var take = Math.Min(45, bytes.Length - offset);
            // 不要把多字节字符切开
            while (take > 1 && offset + take < bytes.Length && (bytes[offset + take] & 0xC0) == 0x80) take--;
            chunks.Add("=?UTF-8?B?" + Convert.ToBase64String(bytes, offset, take) + "?=");
            offset += take;
        }
        return chunks.Count == 1 ? chunks[0] : string.Join(Crlf + " ", chunks);
    }

    /// <summary>解析地址列表，抽出纯地址。</summary>
    public static string[] Addresses(string value)
    {
        if (string.IsNullOrWhiteSpace(value)) return [];
        var result = new List<string>();
        var depth = 0;
        var current = new StringBuilder();
        foreach (var c in value)
        {
            switch (c)
            {
                case '<': depth++; current.Append(c); break;
                case '>': depth = Math.Max(0, depth - 1); current.Append(c); break;
                case ',' or ';' when depth == 0: Add(); break;
                default: current.Append(c); break;
            }
        }
        Add();
        return result.Distinct(StringComparer.OrdinalIgnoreCase).ToArray();

        void Add()
        {
            var item = current.ToString().Trim();
            current.Clear();
            if (item.Length == 0) return;
            var start = item.IndexOf('<');
            var end = item.IndexOf('>', start + 1);
            var address = start >= 0 && end > start ? item[(start + 1)..end].Trim() : item;
            if (address.Contains('@') && address.IndexOf('@') > 0 && address.IndexOf('@') < address.Length - 1) result.Add(address);
        }
    }

    private static string AddressText(string value) => value ?? "";

    internal static (string MediaType, Dictionary<string, string> Parameters) ParseContentType(string value)
    {
        var parameters = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(value)) return ("text/plain", parameters);
        var segments = value.Split(';');
        var mediaType = segments[0].Trim().ToLowerInvariant();
        for (var i = 1; i < segments.Length; i++)
        {
            var part = segments[i].Trim();
            var equals = part.IndexOf('=');
            if (equals <= 0) continue;
            var name = part[..equals].Trim().ToLowerInvariant();
            var val = part[(equals + 1)..].Trim().Trim('"');
            parameters[name] = val;
        }
        return (mediaType, parameters);
    }

    /// <summary>按 charset 解码字节；未知字符集回退 UTF-8。</summary>
    public static string DecodeCharset(byte[] bytes, string? charset)
    {
        if (bytes.Length == 0) return "";
        var encoding = ResolveEncoding(charset);
        try { return encoding.GetString(bytes); }
        catch { return Encoding.UTF8.GetString(bytes); }
    }

    private static Encoding ResolveEncoding(string? charset)
    {
        if (string.IsNullOrWhiteSpace(charset)) return Encoding.UTF8;
        var name = charset.Trim().Trim('"').ToLowerInvariant();
        if (name is "utf8" or "utf-8" or "unicode-1-1-utf-8") return new UTF8Encoding(false);
        if (name is "us-ascii" or "ascii") return Encoding.ASCII;
        if (name is "latin1" or "iso-8859-1" or "iso8859-1" or "windows-1252") return Encoding.Latin1;
        try { return Encoding.GetEncoding(name); }
        catch
        {
            if (name is "gb2312" or "gbk" or "gb18030" or "csgb2312" or "x-gbk")
            {
                var provider = CodePagesShim.Provider;
                if (provider is not null)
                {
                    try
                    {
                        Encoding.RegisterProvider(provider);
                        var codePage = name == "gb18030" ? 54936 : 936;
                        return Encoding.GetEncoding(codePage);
                    }
                    catch { }
                }
            }
            AppLog.Warn($"[MIME] 不支持的字符集 {charset}，按 UTF-8 处理。");
            return Encoding.UTF8;
        }
    }

    // ---------------------------------------------------------------- 组装

    public static byte[] Build(ComposeRequest request, AppConfig config)
    {
        var messageId = string.IsNullOrWhiteSpace(request.MessageId)
            ? $"<{Guid.NewGuid():N}@{config.Domain}>"
            : (request.MessageId.StartsWith('<') ? request.MessageId : $"<{request.MessageId}>");

        var attachments = request.Attachments ?? [];
        var hasHtml = !string.IsNullOrWhiteSpace(request.Html);
        var textPartBytes = Encoding.UTF8.GetBytes(request.Text ?? "");
        var htmlPartBytes = hasHtml ? Encoding.UTF8.GetBytes(request.Html!) : [];

        var headers = new StringBuilder();
        headers.Append("Date: ").Append(FormatDate(DateTimeOffset.UtcNow)).Append(Crlf);
        headers.Append("From: ").Append(FormatAddress(request.From, request.FromDisplay)).Append(Crlf);
        headers.Append("To: ").Append(string.Join(", ", request.To.Select(a => FormatAddress(a, null)))).Append(Crlf);
        if (request.Cc.Length > 0) headers.Append("Cc: ").Append(string.Join(", ", request.Cc.Select(a => FormatAddress(a, null)))).Append(Crlf);
        headers.Append("Subject: ").Append(EncodeHeader(request.Subject ?? "")).Append(Crlf);
        headers.Append("Message-ID: ").Append(messageId).Append(Crlf);
        if (!string.IsNullOrWhiteSpace(request.InReplyTo)) headers.Append("In-Reply-To: ").Append(request.InReplyTo.Trim()).Append(Crlf);
        if (!string.IsNullOrWhiteSpace(request.References)) headers.Append("References: ").Append(request.References.Trim()).Append(Crlf);
        headers.Append("MIME-Version: 1.0").Append(Crlf);

        var body = new MemoryStream();
        if (attachments.Count > 0)
        {
            var mixedBoundary = "mix-" + Guid.NewGuid().ToString("N")[..16];
            headers.Append("Content-Type: multipart/mixed; boundary=\"").Append(mixedBoundary).Append('"').Append(Crlf);
            headers.Append(Crlf);

            WriteBoundary(body, mixedBoundary, false);
            body.Write(hasHtml ? BuildAlternativePart(textPartBytes, htmlPartBytes) : BuildTextPart(textPartBytes));

            foreach (var attachment in attachments)
            {
                WriteBoundary(body, mixedBoundary, false);
                var part = new StringBuilder();
                part.Append("Content-Type: ").Append(attachment.ContentType).Append("; ")
                    .Append(FileNameParameters(attachment.FileName, "name")).Append(Crlf);
                part.Append("Content-Transfer-Encoding: base64").Append(Crlf);
                part.Append("Content-Disposition: ").Append(attachment.Inline ? "inline" : "attachment").Append("; ")
                    .Append(FileNameParameters(attachment.FileName, "filename")).Append(Crlf);
                if (!string.IsNullOrWhiteSpace(attachment.ContentId))
                    part.Append("Content-ID: <").Append(attachment.ContentId.Trim('<', '>')).Append('>').Append(Crlf);
                part.Append(Crlf);
                part.Append(WrapBase64(attachment.Data));
                body.Write(Encoding.ASCII.GetBytes(part.ToString()));
            }
            WriteBoundary(body, mixedBoundary, true);
        }
        else if (hasHtml)
        {
            var boundary = "alt-" + Guid.NewGuid().ToString("N")[..16];
            headers.Append("Content-Type: multipart/alternative; boundary=\"").Append(boundary).Append('"').Append(Crlf);
            headers.Append(Crlf);
            body.Write(BuildAlternativeWithBoundary(textPartBytes, htmlPartBytes, boundary));
        }
        else
        {
            headers.Append("Content-Type: text/plain; charset=UTF-8").Append(Crlf);
            headers.Append("Content-Transfer-Encoding: base64").Append(Crlf);
            headers.Append(Crlf);
            body.Write(Encoding.ASCII.GetBytes(WrapBase64(textPartBytes)));
        }

        var output = new MemoryStream();
        output.Write(Encoding.ASCII.GetBytes(headers.ToString()));
        body.Position = 0;
        body.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] BuildTextPart(byte[] textBytes)
    {
        var part = new StringBuilder();
        part.Append("Content-Type: text/plain; charset=UTF-8").Append(Crlf);
        part.Append("Content-Transfer-Encoding: base64").Append(Crlf);
        part.Append(Crlf);
        part.Append(WrapBase64(textBytes));
        return Encoding.ASCII.GetBytes(part.ToString());
    }

    /// <summary>作为 multipart/mixed 的子部分时，必须带上自己的 Content-Type 头。</summary>
    private static byte[] BuildAlternativePart(byte[] textBytes, byte[] htmlBytes)
    {
        var boundary = "alt-" + Guid.NewGuid().ToString("N")[..16];
        var output = new MemoryStream();
        output.Write(Encoding.ASCII.GetBytes("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"" + Crlf + Crlf));
        output.Write(BuildAlternativeWithBoundary(textBytes, htmlBytes, boundary));
        return output.ToArray();
    }

    /// <summary>附件名参数：ASCII 回退 + RFC 2231 扩展写法，保证中文文件名不乱码。</summary>
    private static string FileNameParameters(string fileName, string parameterName)
    {
        var ascii = new string(fileName.Select(c => c is >= ' ' and <= '~' && c != '"' && c != '\\' ? c : '_').ToArray());
        if (ascii.Length == 0) ascii = "attachment";
        return $"{parameterName}=\"{ascii}\"; {parameterName}*=UTF-8''{Uri.EscapeDataString(fileName)}";
    }

    private static byte[] BuildAlternativeWithBoundary(byte[] textBytes, byte[] htmlBytes, string boundary)
    {
        var output = new MemoryStream();
        WriteBoundary(output, boundary, false);
        output.Write(BuildTextPart(textBytes));
        WriteBoundary(output, boundary, false);
        var html = new StringBuilder();
        html.Append("Content-Type: text/html; charset=UTF-8").Append(Crlf);
        html.Append("Content-Transfer-Encoding: base64").Append(Crlf);
        html.Append(Crlf);
        html.Append(WrapBase64(htmlBytes));
        output.Write(Encoding.ASCII.GetBytes(html.ToString()));
        WriteBoundary(output, boundary, true);
        return output.ToArray();
    }

    private static void WriteBoundary(Stream stream, string boundary, bool closing)
    {
        var line = "--" + boundary + (closing ? "--" : "") + Crlf;
        stream.Write(Encoding.ASCII.GetBytes(line));
    }

    private static string FormatAddress(string address, string? display)
    {
        address = address.Trim().Trim('<', '>');
        if (string.IsNullOrWhiteSpace(display)) return address;
        return $"{EncodeHeader(display)} <{address}>";
    }

    /// <summary>RFC 5322 日期（必须是 ±HHMM 形式的时区）。</summary>
    public static string FormatDate(DateTimeOffset value)
    {
        var offset = value.Offset;
        var sign = offset < TimeSpan.Zero ? "-" : "+";
        var absolute = offset.Duration();
        return value.ToString("ddd, dd MMM yyyy HH:mm:ss ", CultureInfo.InvariantCulture) +
               $"{sign}{absolute.Hours:D2}{absolute.Minutes:D2}";
    }

    private static string WrapBase64(byte[] bytes)
    {
        var encoded = Convert.ToBase64String(bytes);
        var builder = new StringBuilder(encoded.Length + encoded.Length / 76 * 2 + 2);
        for (var index = 0; index < encoded.Length; index += 76)
        {
            builder.Append(encoded, index, Math.Min(76, encoded.Length - index)).Append(Crlf);
        }
        return builder.ToString();
    }

    // ---------------------------------------------------------------- 工具

    private static int IndexOf(byte[] data, string text) => IndexOf(data, 0, text);

    private static int IndexOf(byte[] data, int start, string text)
    {
        var pattern = Encoding.ASCII.GetBytes(text);
        for (var i = start; i + pattern.Length <= data.Length; i++)
        {
            var match = true;
            for (var j = 0; j < pattern.Length; j++)
            {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }
}

/// <summary>
/// 可选注册 .NET 的代码页编码提供程序（用于 GBK/GB18030）。
/// 未引用 System.Text.Encoding.CodePages 包时静默降级为 UTF-8。
/// </summary>
internal static class CodePagesShim
{
    private static EncodingProvider? provider;
    private static bool resolved;

    public static EncodingProvider? Provider
    {
        get
        {
            if (!resolved)
            {
                resolved = true;
                try
                {
                    var type = Type.GetType("System.Text.CodePagesEncodingProvider, System.Text.Encoding.CodePages", throwOnError: false);
                    provider = type?.GetProperty("Instance", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static)?.GetValue(null) as EncodingProvider;
                    if (provider is not null) AppLog.Info("[MIME] 已启用代码页编码支持（GBK/GB18030 可正常解码）。");
                    else AppLog.Warn("[MIME] 未找到代码页编码支持；GBK/GB2312 编码的中文邮件可能解码异常。");
                }
                catch { provider = null; }
            }
            return provider;
        }
    }
}
