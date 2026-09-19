using System.Text;

namespace WpywMail.Native;

public sealed record ParsedMime(string From, string To, string Subject, string MessageId, string Text);

public static class Mime
{
    public static ParsedMime Parse(byte[] raw)
    {
        var value = Encoding.UTF8.GetString(raw).Replace("\r\n", "\n");
        var split = value.IndexOf("\n\n", StringComparison.Ordinal);
        var headerText = split >= 0 ? value[..split] : value;
        var body = split >= 0 ? value[(split + 2)..] : "";
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? current = null;
        foreach (var line in headerText.Split('\n'))
        {
            if ((line.StartsWith(' ') || line.StartsWith('\t')) && current is not null) headers[current] += " " + line.Trim();
            else { var colon = line.IndexOf(':'); if (colon > 0) { current = line[..colon]; headers[current] = line[(colon + 1)..].Trim(); } }
        }
        return new ParsedMime(headers.GetValueOrDefault("From", ""), headers.GetValueOrDefault("To", ""), headers.GetValueOrDefault("Subject", "(无主题)"), headers.GetValueOrDefault("Message-ID", ""), body.TrimEnd());
    }

    public static byte[] Build(string from, string[] to, string subject, string text)
    {
        var body = WrapBase64(Encoding.UTF8.GetBytes(text));
        var value = $"From: {from}\r\nTo: {string.Join(", ", to)}\r\nSubject: {EncodeHeader(subject)}\r\nDate: {DateTimeOffset.UtcNow:R}\r\nMessage-ID: <{Guid.NewGuid():N}@wpyw.site>\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: base64\r\n\r\n{body}\r\n";
        return Encoding.UTF8.GetBytes(value);
    }

    private static string EncodeHeader(string value)
    {
        if (value.All(ch => ch <= 0x7F)) return value;
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(value));
        return $"=?UTF-8?B?{encoded}?=";
    }

    private static string WrapBase64(byte[] bytes)
    {
        var encoded = Convert.ToBase64String(bytes);
        return string.Join("\r\n", Enumerable.Range(0, (encoded.Length + 75) / 76)
            .Select(index => encoded.Substring(index * 76, Math.Min(76, encoded.Length - index * 76))));
    }

    public static string[] Addresses(string value) => value.Split([',', ';'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Select(x => x.Contains('<') ? x[(x.IndexOf('<') + 1)..x.IndexOf('>')] : x).Where(x => x.Contains('@')).ToArray();
}
