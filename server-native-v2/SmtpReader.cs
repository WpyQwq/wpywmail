using System.Text;

namespace WpywMail.Native;

/// <summary>
/// 字节级 SMTP 行读取器。
///
/// 为什么不用 StreamReader：
///   1. StreamReader 只能返回字符串，8bit 正文会被字符集转换破坏；
///   2. StreamReader 会预读缓冲，若之后改从原始流直接读 DATA，属于正文的字节
///      可能已经被吞进它的缓冲区，造成命令/正文错位。
/// 这里让命令与 DATA 共用同一份缓冲区，从根本上避免这两个问题。
/// </summary>
internal sealed class SmtpReader
{
    private const int MaxCommandLine = 8192;
    private static readonly byte[] Crlf = [13, 10];

    private readonly Stream stream;
    private readonly byte[] buffer = new byte[8192];
    private readonly MemoryStream line = new(MaxCommandLine);
    private int start;
    private int end;

    public SmtpReader(Stream stream) => this.stream = stream;

    /// <summary>读一行命令（不含 CRLF），连接关闭返回 null。</summary>
    public async Task<string?> ReadLineAsync(CancellationToken token)
    {
        while (true)
        {
            if (start >= end)
            {
                end = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
                start = 0;
                if (end <= 0) return null;
            }

            var current = buffer[start++];
            if (current == (byte)'\n')
            {
                var bytes = line.ToArray();
                line.SetLength(0);
                var length = bytes.Length;
                if (length > 0 && bytes[length - 1] == (byte)'\r') length--;
                return Encoding.ASCII.GetString(bytes, 0, length);
            }

            line.WriteByte(current);
            if (line.Length > MaxCommandLine) throw new InvalidOperationException("命令行过长，已断开。");
        }
    }

    /// <summary>从同一缓冲区读取恰好 length 个字节（IMAP 的 literal 需要）。</summary>
    public async Task<byte[]> ReadExactlyAsync(int length, CancellationToken token)
    {
        if (length < 0) throw new InvalidOperationException("长度非法。");
        var result = new byte[length];
        var written = 0;
        while (written < length)
        {
            if (start >= end)
            {
                end = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
                start = 0;
                if (end <= 0) throw new IOException("连接在读取 literals 途中关闭。");
            }
            var take = Math.Min(length - written, end - start);
            Buffer.BlockCopy(buffer, start, result, written, take);
            start += take;
            written += take;
        }
        return result;
    }

    /// <summary>
    /// 读取 DATA 段直到单独一行的 "."。按字节忠实处理并做 dot-unstuffing，
    /// 行尾统一为 CRLF。超过 maxBytes 抛 InvalidOperationException。
    /// </summary>
    public async Task<byte[]> ReadDataAsync(int maxBytes, CancellationToken token)
    {
        var message = new MemoryStream();
        line.SetLength(0);

        while (true)
        {
            if (start >= end)
            {
                end = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), token);
                start = 0;
                if (end <= 0) throw new IOException("连接在 DATA 中途关闭。");
            }

            var current = buffer[start++];
            if (current != (byte)'\n')
            {
                line.WriteByte(current);
                if (line.Length > maxBytes) throw new InvalidOperationException("单行过长，已拒绝。");
                continue;
            }

            var text = line.ToArray();
            line.SetLength(0);
            if (text.Length > 0 && text[^1] == (byte)'\r') text = text[..^1];
            if (text.Length == 1 && text[0] == (byte)'.') break;           // DATA 结束
            if (text.Length > 1 && text[0] == (byte)'.') text = text[1..];  // dot-unstuffing

            message.Write(text);
            message.Write(Crlf);
            if (message.Length > maxBytes)
                throw new InvalidOperationException($"邮件超过 {maxBytes / 1024 / 1024} MB 上限，已拒绝。");
        }

        return message.ToArray();
    }
}
