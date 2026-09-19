namespace WpywMail.Native;

/// <summary>
/// SMTP DATA 段的线上编码与还原。
///
/// 为什么要单独抽出来：
///   DKIM 是对「签名那一刻的确切字节」做的哈希。任何在签名之后改写报文的行为
///   （例如把裸 LF 换成 CRLF）都会让接收方算出的正文哈希对不上，签名直接失效。
///   因此约定：**先规范化行尾 → 再签名 → 传输阶段除 dot-stuffing 外不得改动任何字节**。
///   本类同时被发送侧与自检使用，保证两边行为一致。
/// </summary>
internal static class SmtpDataEncoder
{
    private static readonly byte[] Crlf = [13, 10];

    /// <summary>把报文规范化为统一的 CRLF 行尾形式（不加密、不加终止行）。应在 DKIM 签名之前调用。</summary>
    public static byte[] Normalize(byte[] message)
    {
        using var output = new MemoryStream(message.Length + 16);
        var index = 0;
        while (index < message.Length)
        {
            var current = message[index];
            if (current == (byte)'\r')
            {
                output.Write(Crlf);
                index += index + 1 < message.Length && message[index + 1] == (byte)'\n' ? 2 : 1;
                continue;
            }
            if (current == (byte)'\n')
            {
                output.Write(Crlf);
                index++;
                continue;
            }
            output.WriteByte(current);
            index++;
        }
        var bytes = output.ToArray();
        if (bytes.Length == 0 || !EndsWithCrlf(bytes))
        {
            var padded = new byte[bytes.Length + 2];
            Buffer.BlockCopy(bytes, 0, padded, 0, bytes.Length);
            padded[^2] = 13;
            padded[^1] = 10;
            return padded;
        }
        return bytes;
    }

    /// <summary>
    /// 生成 DATA 段实际要写出的字节：行首的点做 dot-stuffing，结尾补 CRLF 与单独一行的 "."。
    /// 除 dot-stuffing 外不改动任何字节，以保证与 DKIM 签名一致。
    /// </summary>
    public static byte[] Encode(byte[] normalizedMessage)
    {
        using var output = new MemoryStream(normalizedMessage.Length + 16);
        var atLineStart = true;
        foreach (var current in normalizedMessage)
        {
            if (atLineStart && current == (byte)'.') output.WriteByte((byte)'.'); // dot-stuffing
            output.WriteByte(current);
            atLineStart = current == (byte)'\n';
        }
        if (output.Length == 0 || output.GetBuffer()[output.Length - 1] != (byte)'\n') output.Write(Crlf);
        output.Write([(byte)'.', 13, 10]);
        return output.ToArray();
    }

    /// <summary>接收侧还原：去掉终止行并做 dot-unstuffing（自检用于模拟收件端）。</summary>
    public static byte[] Decode(byte[] wire)
    {
        // 去掉结尾的 ".\r\n"
        var end = wire.Length;
        if (end >= 3 && wire[end - 3] == (byte)'.' && wire[end - 2] == 13 && wire[end - 1] == 10)
            end -= 3;
        else if (end >= 2 && wire[end - 2] == (byte)'.' && wire[end - 1] == 10)
            end -= 2;

        using var output = new MemoryStream(end);
        var atLineStart = true;
        for (var index = 0; index < end; index++)
        {
            var current = wire[index];
            if (atLineStart && current == (byte)'.' && index + 1 < end && wire[index + 1] == (byte)'.')
            {
                index++; // 去掉填充的点
            }
            output.WriteByte(wire[index]);
            atLineStart = wire[index] == (byte)'\n';
        }
        return output.ToArray();
    }

    private static bool EndsWithCrlf(byte[] bytes) =>
        bytes.Length >= 2 && bytes[^2] == 13 && bytes[^1] == 10;
}
