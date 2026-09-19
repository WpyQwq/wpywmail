using System.Security.Cryptography;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// 存储层自检：**同一套断言在 json 与 sqlite 两个后端上各跑一遍**，
/// 保证两套实现语义一致（这样 Storage.Provider 才能真正做到一键切换/回滚）。
/// </summary>
public static partial class SelfTest
{
    private static void TestStorageBackends()
    {
        foreach (var provider in new[] { "json", "sqlite" })
        {
            var config = new AppConfig
            {
                Domain = "wpy.email",
                Hostname = "mail.example.com",
                AdminEmail = "store@wpy.email",
                AdminPassword = "selftest-password-1234",
                DataDirectory = Path.Combine(Path.GetTempPath(), $"wpyw-store-{provider}-{Guid.NewGuid().ToString("N")[..8]}"),
                Dkim = new DkimConfig { Enabled = false },
                Storage = new StorageConfig { Provider = provider },
            };
            Directory.CreateDirectory(config.DataDirectory);
            try { RunStorageChecks(config, provider); }
            catch (Exception ex) { Fail($"[{provider}] 存储自检", $"抛出异常：{ex.Message}"); }
            finally { try { Directory.Delete(config.DataDirectory, true); } catch { } }
        }
    }

    private static void RunStorageChecks(AppConfig config, string provider)
    {
        using var store = Program.CreateStore(config);
        var admin = config.AdminEmail;

        Check($"[{provider}] 自动创建的管理员可认证", store.Authenticate(admin, config.AdminPassword) is not null, "");
        Check($"[{provider}] 错误口令被拒绝", store.Authenticate(admin, "wrong-password-1234") is null, "");
        Check($"[{provider}] 本地地址判定", store.IsLocalAddress(admin) && !store.IsLocalAddress("nobody@example.com"), "");

        // ---- 报文原文往返（逐字节）----
        var raw = Mime.Build(new ComposeRequest("张三 <a@example.com>", "张三", [admin], [],
            "存储自检：中文主题", "存储自检正文，包含中文与全角标点（）、——。"), config);
        var parsed = Mime.Parse(raw);
        var first = store.SaveMessage(new MailMessage
        {
            OwnerEmail = admin, Folder = "inbox", From = parsed.From, To = parsed.To, Subject = parsed.Subject,
            Text = parsed.Text, MessageId = parsed.MessageId, Date = DateTimeOffset.UtcNow, Unread = true,
        }, raw);

        var readBack = store.ReadRaw(first.RawPath);
        Check($"[{provider}] 报文原文逐字节读回", readBack.SequenceEqual(raw), $"{raw.Length} 字节");

        // ---- UID 单调 ----
        var second = store.SaveMessage(new MailMessage
        {
            OwnerEmail = admin, Folder = "inbox", From = "b@example.com", To = admin,
            Subject = "第二封", Text = "第二封正文", Date = DateTimeOffset.UtcNow.AddSeconds(1), Unread = true,
        }, raw);
        Check($"[{provider}] IMAP UID 同文件夹内递增", second.Uid == first.Uid + 1, $"{first.Uid} → {second.Uid}");
        Check($"[{provider}] 未读计数正确", store.CountUnseen(admin, "inbox") == 2, $"{store.CountUnseen(admin, "inbox")}");

        // ---- 标记已读 / 星标 / 统计 ----
        store.MarkRead(admin, first.Id, true);
        var unreadAfter = store.CountUnseen(admin, "inbox");
        var stats = store.Stats(admin);
        var inboxCount = (int)stats.GetType().GetProperty("inbox")!.GetValue(stats)!;
        var unreadCount = (int)stats.GetType().GetProperty("unread")!.GetValue(stats)!;
        Check($"[{provider}] 标记已读后未读数下降", unreadAfter == 1 && unreadCount == 1, $"{unreadAfter}/{unreadCount}");
        Check($"[{provider}] 统计的收件箱总数", inboxCount == 2, $"{inboxCount}");

        store.SetStar(admin, second.Id, true);
        var starred = (int)store.Stats(admin).GetType().GetProperty("starred")!.GetValue(store.Stats(admin))!;
        Check($"[{provider}] 星标计数", starred == 1, $"{starred}");

        // ---- 分页与搜索 ----
        var (total, page) = store.ListMessagesPage(admin, "inbox", "", false, false, 1, 0);
        Check($"[{provider}] 分页：总数与页大小", total == 2 && page.Count == 1, $"total={total} 页={page.Count}");
        var (unreadTotal, _) = store.ListMessagesPage(admin, "inbox", "", true, false, 10, 0);
        Check($"[{provider}] 分页：未读过滤", unreadTotal == 1, $"{unreadTotal}");
        var hits = store.ListMessages(admin, "", "存储自检正文");
        Check($"[{provider}] 中文正文搜索命中", hits.Count == 1, $"命中 {hits.Count}");
        var miss = store.ListMessages(admin, "", "绝对不存在的关键词xyzzy");
        Check($"[{provider}] 搜索不误报", miss.Count == 0, $"命中 {miss.Count}");

        // ---- 会话 ----
        var session = store.CreateSession(admin, 30);
        Check($"[{provider}] 会话创建与校验", store.GetSession(session.Token)?.Email == admin, "");
        store.RemoveSession(session.Token);
        Check($"[{provider}] 会话删除后失效", store.GetSession(session.Token) is null, "");

        // ---- 队列 ----
        var queued = store.QueueOutbound(admin, ["someone@example.com"], "队列自检", "正文", raw);
        var due = store.TakeDueQueue(10);
        Check($"[{provider}] 出站任务入队并可取出", due.Count == 1 && due[0].MessageId == queued.Id, $"{due.Count} 条");
        if (due.Count > 0)
        {
            store.CompleteQueue(due[0]);
            var queueStats = (int)store.Stats(admin).GetType().GetProperty("queue")!.GetValue(store.Stats(admin))!;
            Check($"[{provider}] 完成后队列清空", queueStats == 0, $"{queueStats}");
            var sent = store.GetById(queued.Id)!;
            Check($"[{provider}] 发件箱状态更新为 sent", sent.DeliveryStatus == "sent", sent.DeliveryStatus);
        }

        // ---- 删除：inbox → trash → 永久 ----
        store.DeleteMessage(admin, first.Id, permanent: false);
        var moved = store.GetMessage(admin, first.Id);
        Check($"[{provider}] 删除先移入垃圾箱", moved?.Folder == "trash", moved?.Folder ?? "(null)");

        // 永久删除 + 原文回收：用一封**内容唯一**的报文来验证。
        // （不能拿 first 来验：它的字节被别的邮件/队列项共享，按内容去重后本就不该被回收。）
        var doomedRaw = Mime.Build(new ComposeRequest("delete@example.com", "删除自检", [admin], [],
            "永久删除自检专用报文 " + Guid.NewGuid().ToString("N")[..8], "这封邮件的字节应当独一无二，删除后原文必须一起消失。"), config);
        var doomed = store.SaveMessage(new MailMessage
        {
            OwnerEmail = admin, Folder = "inbox", From = "delete@example.com", To = admin,
            Subject = "永久删除自检", Text = "唯一内容", Date = DateTimeOffset.UtcNow.AddMinutes(1), Unread = false,
        }, doomedRaw);
        var doomedPath = doomed.RawPath;
        store.DeleteMessage(admin, doomed.Id, permanent: true);
        Check($"[{provider}] 永久删除后查不到", store.GetMessage(admin, doomed.Id) is null, "");
        Check($"[{provider}] 永久删除同时回收了原文", ThrowsOnMissing(() => store.ReadRaw(doomedPath)), doomedPath);

        // ---- 本地投递（同域收件人）----
        var delivered = store.DeliverLocal(admin, raw, "someone@example.com");
        Check($"[{provider}] 本地投递入库为一封未读邮件", delivered is not null && delivered.Unread, "");

        // ---- 附件 ----
        var attachmentStore = store.SaveAttachment(Encoding.UTF8.GetBytes("附件内容"), "测试.txt");
        Check($"[{provider}] 附件写入并读回",
            Encoding.UTF8.GetString(store.ReadAttachment(attachmentStore)) == "附件内容", "");

        // ---- SQLite 专属：大对象按内容去重 ----
        if (store is SqliteStore)
        {
            var a = store.SaveRaw(raw);
            var b = store.SaveRaw(raw);
            Check("[sqlite] 相同报文内容按哈希去重（同一 blob）", a == b, $"{a} / {b}");
            var report = ((SqliteStore)store).StorageReport();
            Check("[sqlite] 大对象压缩生效（存储小于原文）",
                report.BlobStoredBytes > 0 && report.BlobStoredBytes < report.BlobRawBytes,
                $"{report.BlobRawBytes} → {report.BlobStoredBytes}");
            Check("[sqlite] 无孤儿大对象或可清理", report.Orphans == 0 || ((SqliteStore)store).Compact() >= 0,
                $"孤儿 {report.Orphans}");
        }

        // ---- 彻底删除账号（--purge-user 用的就是这一套；两个后端必须同一契约）
        var doomedUser = $"purge-{provider}@wpy.email";
        store.CreateUser(doomedUser, "Str0ng-Pass-2026", "待删账号");
        store.CreateSession(doomedUser, 30);
        store.SaveVerificationCode(new VerificationCode
        {
            Email = doomedUser, Purpose = "register",
            Salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            CodeHash = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)),
            ExpiresAt = DateTimeOffset.UtcNow.AddMinutes(10), CreatedAt = DateTimeOffset.UtcNow,
        });
        var doomedMail = store.SaveMessage(new MailMessage
        {
            OwnerEmail = doomedUser, Folder = "inbox", From = "x@example.com", To = doomedUser,
            Subject = "待删账号的邮件", Text = "内容 " + Guid.NewGuid().ToString("N")[..8],
            Date = DateTimeOffset.UtcNow, Unread = true,
        }, null);
        foreach (var mail in store.ListMessages(doomedUser, "", "")) store.DeleteMessage(doomedUser, mail.Id, permanent: true);
        Check($"[{provider}] 删除账号前邮件确实属于它", store.GetMessage(doomedUser, doomedMail.Id) is null, "");
        Check($"[{provider}] 删除账号返回成功", store.DeleteUser(doomedUser), "");
        Check($"[{provider}] 删除后查不到账号", store.FindUserAnyState(doomedUser) is null, "");
        Check($"[{provider}] 删除后会话与验证码一并清掉",
            store.ListSessions(doomedUser).Count == 0 && store.FindVerificationCode(doomedUser, "register") is null, "");
        Check($"[{provider}] 重复删除返回 false（幂等）", !store.DeleteUser(doomedUser), "");
    }

    private static bool ThrowsOnMissing(Action action)
    {
        try { action(); return false; }
        catch { return true; }
    }
}
