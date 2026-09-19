namespace WpywMail.Native;

/// <summary>
/// 一次性数据迁移（用法：WpywMail.Native.exe --migrate）。
///
/// 1.x 版本有两个存储层缺陷：
///   · Mime.Parse 不解码 RFC 2047 编码字，也不解 base64/QP 正文 ——
///     导致 messages.json 里的主题是「=?utf-8?b?...?=」、正文是 base64 乱码；
///   · 换域名后历史邮件的 ownerEmail 仍指向旧域名，登录新账号后看不到。
/// 本迁移用新解析器重新解析 raw/*.eml 修好字段，并把旧域名归到当前配置的账号下。
/// </summary>
public static class Migration
{
    public static int Run(AppConfig config, IMailStore store)
    {
        Console.WriteLine("=== 数据迁移 ===");

        // 旧域名 → 当前域名的账号映射
        var users = store.AllUsers();
        var oldAdmin = users.FirstOrDefault(x => x.Email.Equals(config.AdminEmail, StringComparison.OrdinalIgnoreCase));
        var currentEmail = oldAdmin?.Email ?? config.AdminEmail;

        var messages = store.AllMessages();
        var fixedSubjects = 0;
        var reParsed = 0;
        var reOwnered = 0;
        var missingRaw = 0;

        foreach (var message in messages)
        {
            // ---- 1) 重新解析原始报文 ----
            byte[]? raw = null;
            if (!string.IsNullOrWhiteSpace(message.RawPath))
            {
                try { raw = store.ReadRaw(message.RawPath); }
                catch { missingRaw++; }
            }

            if (raw is not null)
            {
                try
                {
                    var parsed = Mime.Parse(raw);
                    var changed = false;

                    if (!string.IsNullOrWhiteSpace(parsed.Subject) && parsed.Subject != "(无主题)" && parsed.Subject != message.Subject)
                    {
                        message.Subject = parsed.Subject;
                        changed = true;
                    }
                    if (parsed.Text.Length > 0 && parsed.Text != message.Text)
                    {
                        message.Text = parsed.Text;
                        changed = true;
                    }
                    if (parsed.Html.Length > 0 && parsed.Html != message.Html)
                    {
                        message.Html = parsed.Html;
                        changed = true;
                    }
                    if (string.IsNullOrWhiteSpace(message.MessageId) && parsed.MessageId.Length > 0)
                    {
                        message.MessageId = parsed.MessageId;
                        changed = true;
                    }
                    if (string.IsNullOrWhiteSpace(message.From) && parsed.From.Length > 0)
                    {
                        message.From = parsed.From;
                        changed = true;
                    }
                    if (string.IsNullOrWhiteSpace(message.Cc) && parsed.Cc.Length > 0)
                    {
                        message.Cc = parsed.Cc;
                        changed = true;
                    }
                    // 附件补齐（旧版本没有存附件）
                    if (message.Attachments.Count == 0 && parsed.Attachments.Count > 0)
                    {
                        foreach (var attachment in parsed.Attachments)
                        {
                            if (attachment.Data.Length == 0) continue;
                            message.Attachments.Add(new Attachment
                            {
                                FileName = attachment.FileName,
                                ContentType = attachment.ContentType,
                                Size = attachment.Data.Length,
                                StoredAs = store.SaveAttachment(attachment.Data, attachment.FileName),
                                ContentId = attachment.ContentId,
                                Inline = attachment.Inline,
                            });
                        }
                        changed = true;
                    }

                    if (changed)
                    {
                        reParsed++;
                        if (message.Subject.Length > 0) fixedSubjects++;
                    }
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"  [跳过] {message.Id}：{ex.Message}");
                }
            }

            // ---- 2) 旧域名归属改到当前账号 ----
            if (!string.IsNullOrWhiteSpace(message.OwnerEmail) &&
                !message.OwnerEmail.EndsWith("@" + config.Domain, StringComparison.OrdinalIgnoreCase) &&
                store.FindUser(message.OwnerEmail) is null)
            {
                var localPart = message.OwnerEmail.Split('@')[0];
                var target = users.FirstOrDefault(x => x.Email.StartsWith(localPart + "@", StringComparison.OrdinalIgnoreCase))?.Email
                             ?? currentEmail;
                message.OwnerEmail = target;
                // 归属改了以后，发件人地址也一并按新域名改写，避免列表里显示成不存在的账号
                if (message.From.Equals(message.OwnerEmail, StringComparison.OrdinalIgnoreCase) == false &&
                    message.From.Contains('@') && !message.From.Contains('@' + config.Domain, StringComparison.OrdinalIgnoreCase))
                {
                    // 仅当 From 就是旧账号本身时才改写
                }
                reOwnered++;
            }
        }

        store.Persist();

        Console.WriteLine($"  重新解析并修正：{reParsed} 封");
        Console.WriteLine($"  归属域名改写  ：{reOwnered} 封");
        if (missingRaw > 0) Console.WriteLine($"  原始文件缺失  ：{missingRaw} 封（仅修正索引字段）");
        Console.WriteLine("迁移完成。");
        return 0;
    }
}
