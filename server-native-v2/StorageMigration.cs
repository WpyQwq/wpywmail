using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WpywMail.Native;

/// <summary>
/// 存储后端之间的数据搬迁。
///
/// 正向（JSON → SQLite）：把 users/messages/queue/sessions 全部导入数据库，
/// 报文原文与附件读文件后进 blobs 表（gzip + 内容去重），并**逐封校验**
/// 「从数据库读回来的字节」与「原文件字节」SHA256 完全一致，之后才允许删除源文件。
///
/// 反向（SQLite → JSON）：把 blobs 还原成 raw/ 与 attachments/ 文件并重写 JSON，
/// 用于一键回滚。
/// </summary>
public static class StorageMigration
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    private static T? ReadJson<T>(string path)
    {
        if (!File.Exists(path)) return default;
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(path), Json); }
        catch (Exception ex) { AppLog.Error($"[迁移] 读取 {Path.GetFileName(path)} 失败：{ex.Message}"); return default; }
    }

    private static long DirectoryBytes(string path) =>
        Directory.Exists(path) ? Directory.GetFiles(path, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length) : 0;

    private static string Sha(byte[] data) => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

    // ------------------------------------------------------------------ 正向

    public static int ToSqlite(AppConfig config, bool deleteSourceFiles)
    {
        var dataDir = config.DataDirectory;
        var usersPath = Path.Combine(dataDir, "users.json");
        var messagesPath = Path.Combine(dataDir, "messages.json");
        var queuePath = Path.Combine(dataDir, "queue.json");
        var sessionsPath = Path.Combine(dataDir, "sessions.json");

        var users = ReadJson<List<MailUser>>(usersPath) ?? [];
        var messages = ReadJson<List<MailMessage>>(messagesPath) ?? [];
        var queue = ReadJson<List<QueueItem>>(queuePath) ?? [];
        var sessions = ReadJson<List<SessionRecord>>(sessionsPath) ?? [];

        if (messages.Count == 0 && users.Count == 0)
        {
            Console.WriteLine("没有可迁移的数据（users.json / messages.json 为空或不存在）。");
            return 1;
        }

        var beforeRaw = DirectoryBytes(Path.Combine(dataDir, "raw"));
        var beforeAttachments = DirectoryBytes(Path.Combine(dataDir, "attachments"));
        var beforeJson = new[] { usersPath, messagesPath, queuePath, sessionsPath }
            .Where(File.Exists).Sum(p => new FileInfo(p).Length);

        Console.WriteLine($"源数据：用户 {users.Count}，邮件 {messages.Count}，队列 {queue.Count}，会话 {sessions.Count}");
        Console.WriteLine($"源占用：raw {beforeRaw:N0} B + attachments {beforeAttachments:N0} B + JSON {beforeJson:N0} B");

        using var store = new SqliteStore(config);
        var existing = (int)store.StorageReport().Messages;
        if (existing > 0)
        {
            Console.WriteLine($"数据库里已有 {existing} 封邮件，将按 id 覆盖导入（幂等）。");
        }

        foreach (var user in users) store.ImportUser(user);

        // UID 唯一性修复：数据库上有 (owner, folder, uid) 唯一索引
        var used = new HashSet<(string, string, int)>();
        var nextUid = new Dictionary<(string, string), int>();
        var verified = new List<(MailMessage Message, string OriginalSha, bool HadFile)>();
        var imported = 0;
        var missingRaw = 0;

        foreach (var message in messages.OrderBy(m => m.Date))
        {
            message.OwnerEmail = (message.OwnerEmail ?? "").ToLowerInvariant();
            message.Folder = (message.Folder ?? "inbox").ToLowerInvariant();

            var key = (message.OwnerEmail, message.Folder);
            if (!nextUid.TryGetValue(key, out var next)) next = 1;
            var uid = message.Uid;
            if (uid <= 0 || !used.Add((key.Item1, key.Item2, uid)))
            {
                while (used.Contains((key.Item1, key.Item2, next))) next++;
                uid = next;
                used.Add((key.Item1, key.Item2, uid));
            }
            message.Uid = uid;
            next = Math.Max(next, uid + 1);
            nextUid[key] = next;

            // 报文原文：文件 → blobs
            var originalSha = "";
            var hadFile = false;
            if (!string.IsNullOrWhiteSpace(message.RawPath) && !message.RawPath.StartsWith("db:", StringComparison.OrdinalIgnoreCase))
            {
                var full = Path.Combine(dataDir, message.RawPath);
                if (File.Exists(full))
                {
                    var bytes = File.ReadAllBytes(full);
                    originalSha = Sha(bytes);
                    hadFile = true;
                    message.RawPath = store.SaveRaw(bytes);
                    message.Size = bytes.Length;
                }
                else
                {
                    missingRaw++;
                    message.RawPath = "";
                }
            }

            // 附件：文件 → blobs
            foreach (var attachment in message.Attachments)
            {
                if (string.IsNullOrWhiteSpace(attachment.StoredAs) ||
                    attachment.StoredAs.StartsWith("db:", StringComparison.OrdinalIgnoreCase)) continue;
                var full = Path.Combine(dataDir, attachment.StoredAs);
                if (File.Exists(full)) attachment.StoredAs = store.SaveAttachment(File.ReadAllBytes(full), attachment.FileName);
            }

            store.SaveMessage(message);
            verified.Add((message, originalSha, hadFile));
            imported++;
        }

        foreach (var item in queue) store.ImportQueueItem(item);
        var now = DateTimeOffset.UtcNow;
        foreach (var session in sessions.Where(s => s.Expires > now)) store.ImportSession(session);

        // ---- 校验：从数据库读回来的字节必须与原文件逐字节一致 ----
        Console.WriteLine("校验中（逐封比对 SHA256）……");
        var bad = 0;
        foreach (var (message, originalSha, hadFile) in verified)
        {
            if (!hadFile || message.RawPath.Length == 0) continue;
            try
            {
                var back = store.ReadRaw(message.RawPath);
                if (Sha(back) != originalSha)
                {
                    bad++;
                    Console.Error.WriteLine($"  [不一致] {message.Id} {message.Subject}");
                }
            }
            catch (Exception ex)
            {
                bad++;
                Console.Error.WriteLine($"  [读取失败] {message.Id}：{ex.Message}");
            }
        }

        var report = store.StorageReport();

        Console.WriteLine();
        Console.WriteLine($"导入完成：邮件 {imported} 封，队列 {queue.Count} 条，会话 {sessions.Count} 个" +
                          (missingRaw > 0 ? $"，{missingRaw} 封缺少原始报文文件" : ""));
        Console.WriteLine($"入库大对象：原始 {report.BlobRawBytes:N0} B → 存储 {report.BlobStoredBytes:N0} B" +
                          (report.BlobRawBytes > 0 ? $"（{(100.0 * report.BlobStoredBytes / report.BlobRawBytes):F0}%，{report.BlobGzipped} 个压缩）" : ""));
        Console.WriteLine($"数据库文件：{report.DbBytes:N0} B + WAL {report.WalBytes:N0} B");
        Console.WriteLine($"校验结果：SHA256 不一致 {bad} 封");

        if (bad > 0)
        {
            Console.Error.WriteLine("存在校验失败，已保留源文件，请勿删除。");
            return 2;
        }

        if (!deleteSourceFiles)
        {
            Console.WriteLine("源文件已保留（想释放空间请加 --delete-source 重跑）。");
            return 0;
        }

        // ---- 删源文件（校验已全部通过才走到这里）----
        var deleted = 0;
        long freed = 0;
        foreach (var file in Directory.GetFiles(Path.Combine(dataDir, "raw"), "*.eml", SearchOption.TopDirectoryOnly))
        {
            freed += new FileInfo(file).Length;
            File.Delete(file);
            deleted++;
        }
        var attachmentDir = Path.Combine(dataDir, "attachments");
        foreach (var file in Directory.GetFiles(attachmentDir, "*", SearchOption.TopDirectoryOnly))
        {
            freed += new FileInfo(file).Length;
            File.Delete(file);
            deleted++;
        }
        Console.WriteLine($"已删除源文件 {deleted} 个，释放 {freed:N0} B");
        Console.WriteLine($"提示：JSON 索引文件（users/messages/queue/sessions.json）保留未删，便于随时回滚。");
        return 0;
    }

    // ------------------------------------------------------------------ 反向

    public static int ToJson(AppConfig config)
    {
        var dataDir = config.DataDirectory;
        using var store = new SqliteStore(config);

        var messages = store.AllMessages().ToList();
        var users = store.AllUsers().ToList();
        var queue = store.AllQueueItems().ToList();
        var sessions = store.AllSessions().ToList();

        var rawDir = Path.Combine(dataDir, "raw");
        var attachmentDir = Path.Combine(dataDir, "attachments");
        Directory.CreateDirectory(rawDir);
        Directory.CreateDirectory(attachmentDir);

        var exported = new Dictionary<long, string>();
        foreach (var (id, data) in store.ExportBlobs())
        {
            // 同一个 blob 可能被多封邮件/附件引用，这里各导出一份文件（回滚场景不追求去重）
            var name = $"{DateTime.UtcNow:yyyyMMddHHmmss}-{id}{GuessExtension(data)}";
            var relative = Path.Combine("raw", name);
            File.WriteAllBytes(Path.Combine(dataDir, relative), data);
            exported[id] = relative;
        }

        static string GuessExtension(byte[] data) =>
            data.Length >= 4 && data[0] == 0x50 && data[1] == 0x4B ? ".zip" : ".eml";

        foreach (var message in messages)
        {
            if (message.RawPath.StartsWith("db:", StringComparison.OrdinalIgnoreCase) &&
                long.TryParse(message.RawPath.AsSpan(3), out var blobId) && exported.TryGetValue(blobId, out var path))
                message.RawPath = path;
            foreach (var attachment in message.Attachments)
            {
                if (attachment.StoredAs.StartsWith("db:", StringComparison.OrdinalIgnoreCase) &&
                    long.TryParse(attachment.StoredAs.AsSpan(3), out var attId) && exported.TryGetValue(attId, out var attPath))
                {
                    var target = Path.Combine("attachments", Path.GetFileName(attPath));
                    File.Copy(Path.Combine(dataDir, attPath), Path.Combine(dataDir, target), true);
                    attachment.StoredAs = target;
                }
            }
        }

        File.WriteAllText(Path.Combine(dataDir, "messages.json"), JsonSerializer.Serialize(messages, Json), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(dataDir, "users.json"), JsonSerializer.Serialize(users, Json), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(dataDir, "queue.json"), JsonSerializer.Serialize(queue, Json), new UTF8Encoding(false));
        File.WriteAllText(Path.Combine(dataDir, "sessions.json"), JsonSerializer.Serialize(sessions, Json), new UTF8Encoding(false));

        Console.WriteLine($"已导出：邮件 {messages.Count} 封，用户 {users.Count}，队列 {queue.Count}，会话 {sessions.Count}");
        Console.WriteLine($"报文文件 {exported.Count} 个 → {rawDir}");
        Console.WriteLine("把 appsettings.json 的 Storage.Provider 改回 json 即可用这套数据启动。");
        return 0;
    }

    // ------------------------------------------------------------------ 状态

    public static int Status(AppConfig config)
    {
        var dataDir = config.DataDirectory;
        var rawBytes = DirectoryBytes(Path.Combine(dataDir, "raw"));
        var attachmentBytes = DirectoryBytes(Path.Combine(dataDir, "attachments"));
        var jsonBytes = new[] { "users.json", "messages.json", "queue.json", "sessions.json" }
            .Select(f => Path.Combine(dataDir, f)).Where(File.Exists).Sum(p => new FileInfo(p).Length);

        Console.WriteLine($"当前配置的后端：{config.Storage.Provider}");
        Console.WriteLine($"raw/        {rawBytes,12:N0} B  ({Directory.GetFiles(Path.Combine(dataDir, "raw"), "*").Length} 个文件)");
        Console.WriteLine($"attachments/{attachmentBytes,12:N0} B  ({Directory.GetFiles(Path.Combine(dataDir, "attachments"), "*").Length} 个文件)");
        Console.WriteLine($"JSON 索引    {jsonBytes,12:N0} B");

        var dbPath = string.IsNullOrWhiteSpace(config.Storage.DatabasePath)
            ? Path.Combine(dataDir, "wpywmail.db") : config.Storage.DatabasePath;
        if (!File.Exists(dbPath))
        {
            Console.WriteLine("SQLite 数据库：尚未创建");
            return 0;
        }

        using var store = new SqliteStore(config);
        var report = store.StorageReport();

        Console.WriteLine($"SQLite      {report.DbBytes + report.WalBytes,12:N0} B  ({dbPath})");
        Console.WriteLine($"  邮件 {report.Messages} 封，大对象 {report.Blobs} 个" +
                          $"（原始 {report.BlobRawBytes:N0} B → 存储 {report.BlobStoredBytes:N0} B，" +
                          $"其中 {report.BlobGzipped} 个启用了压缩）");
        Console.WriteLine($"  正文列合计 {report.TextBytes:N0} B（最大一封 {report.LargestTextBytes:N0} B：{Trim(report.LargestTextSubject)}）");
        Console.WriteLine($"  页统计：{report.PageCount} 页 × {report.PageSize} B = {report.TotalBytes:N0} B，" +
                          $"其中空闲 {report.FreeBytes:N0} B" +
                          (report.FreeBytes > 0 ? "（用 --vacuum 回收；注意 VACUUM 需要约 2 倍临时空间，且应在服务停止时做）" : ""));
        Console.WriteLine($"  孤儿大对象 {report.Orphans} 个（用 --compact 清理）");
        return 0;
    }

    private static string Trim(string text) =>
        string.IsNullOrEmpty(text) ? "(无)" : text.Length <= 24 ? text : text[..24] + "…";

    public static int Compact(AppConfig config)
    {
        using var store = new SqliteStore(config);
        var removed = store.Compact();
        Console.WriteLine($"已清理孤儿大对象 {removed} 个。");
        return Status(config);
    }

    /// <summary>合并 WAL 并回收空闲页，把数据库文件压到实际大小。</summary>
    public static int Vacuum(AppConfig config)
    {
        using var store = new SqliteStore(config);
        var before = store.StorageReport();
        Console.WriteLine($"整理前：主库 {before.DbBytes:N0} B + WAL {before.WalBytes:N0} B，空闲页 {before.FreeBytes:N0} B");
        store.Vacuum();     // VACUUM：回收空闲页
        store.Persist();    // 再把 VACUUM 期间产生的 WAL 归并回主库并截断
        var after = store.StorageReport();
        Console.WriteLine($"整理后：主库 {after.DbBytes:N0} B + WAL {after.WalBytes:N0} B，空闲页 {after.FreeBytes:N0} B");
        Console.WriteLine($"实际占用：{(before.DbBytes + before.WalBytes):N0} B → {(after.DbBytes + after.WalBytes):N0} B" +
                          $"（释放 {(before.DbBytes + before.WalBytes) - (after.DbBytes + after.WalBytes):N0} B）");
        return 0;
    }
}
