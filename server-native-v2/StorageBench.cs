using System.Diagnostics;

namespace WpywMail.Native;

/// <summary>
/// 存储后端基准测试：同一份负载分别跑 JSON 与 SQLite 两套实现，输出可对比的数字。
///
/// 关注点（也是 JSON 实现真正的瓶颈）：
///   1. 入库：JSON 每存一封都要把**全部邮件**重新序列化并整文件重写（O(N)/次）；
///   2. 单条改动（标记已读）：同上 —— 这是最容易被放大的操作（IMAP 客户端一打开收件箱就会批量改）；
///   3. 列表 / 未读数 / 统计 / 搜索：JSON 全是全表扫描。
/// </summary>
public static class StorageBench
{
    public static int Run(AppConfig baseConfig, int count, int mutationSamples)
    {
        count = Math.Clamp(count, 20, 20_000);
        mutationSamples = Math.Clamp(mutationSamples, 10, count);

        Console.WriteLine($"=== 存储后端基准测试（{count} 封邮件，单条改动抽样 {mutationSamples} 次）===");
        Console.WriteLine();

        var root = Path.Combine(Path.GetTempPath(), "wpyw-bench-" + Guid.NewGuid().ToString("N")[..8]);
        var jsonDir = Path.Combine(root, "json");
        var sqliteDir = Path.Combine(root, "sqlite");
        Directory.CreateDirectory(jsonDir);
        Directory.CreateDirectory(sqliteDir);

        var jsonConfig = Clone(baseConfig, jsonDir, "json", fullText: false);
        var sqliteConfig = Clone(baseConfig, sqliteDir, "sqlite", fullText: false);
        var ftsDir = Path.Combine(root, "sqlite-fts");
        Directory.CreateDirectory(ftsDir);
        var ftsConfig = Clone(baseConfig, ftsDir, "sqlite", fullText: true);

        try
        {
            var json = Measure("JSON（整文件重写）", jsonConfig, count, mutationSamples);
            var sqlite = Measure("SQLite（WAL + 索引）", sqliteConfig, count, mutationSamples);
            var sqliteFts = Measure("SQLite + FTS5 全文索引", ftsConfig, count, mutationSamples);

            Console.WriteLine();
            Console.WriteLine($"{"操作",-22}{"JSON",16}{"SQLite",16}{"提升",12}");
            Console.WriteLine(new string('-', 68));
            Row("入库 每封", json.InsertPerOp, sqlite.InsertPerOp, "ms");
            Row("标记已读 每次", json.MutatePerOp, sqlite.MutatePerOp, "ms");
            Row("收件箱首页(50条) 每次", json.ListPerOp, sqlite.ListPerOp, "ms");
            Row("未读数 每次", json.UnreadPerOp, sqlite.UnreadPerOp, "ms");
            Row("统计 每次", json.StatsPerOp, sqlite.StatsPerOp, "ms");
            Row("搜索 每次", json.SearchPerOp, sqlite.SearchPerOp, "ms");
            Row("入库总计", json.InsertTotal, sqlite.InsertTotal, "ms");
            Row("磁盘占用", json.Bytes, sqlite.Bytes, "B");
            Row("内存增量", json.Memory, sqlite.Memory, "B");

            Console.WriteLine();
            Console.WriteLine($"明细：JSON → {json.Detail}");
            Console.WriteLine($"      SQLite → {sqlite.Detail}");
            Console.WriteLine($"      SQLite+FTS5 → {sqliteFts.Detail}");
            Console.WriteLine();
            Console.WriteLine("全文检索开关的取舍（同一份数据）：");
            Console.WriteLine($"  搜索 每次：LIKE 扫描 {sqlite.SearchPerOp:N2} ms / 占用 {sqlite.Bytes:N0} B" +
                              $"   ←→   FTS5 {sqliteFts.SearchPerOp:N2} ms / 占用 {sqliteFts.Bytes:N0} B" +
                              $"（索引多占 {sqliteFts.Bytes - sqlite.Bytes:N0} B）");
            Console.WriteLine();
            Console.WriteLine($"磁盘对比：JSON 共 {json.Bytes:N0} B，SQLite 共 {sqlite.Bytes:N0} B" +
                              (sqlite.Bytes > 0 ? $"（{(double)json.Bytes / sqlite.Bytes:F2}×）" : ""));
            Console.WriteLine();
            Console.WriteLine("结论：SQLite 的「入库」与「单条改动」耗时与邮件量基本无关（索引定位单行）；");
            Console.WriteLine("      JSON 实现每次改动都要重写全部邮件，随邮件量增长呈超线性，且常驻内存随邮箱增长。");
            Console.WriteLine("      列表首页两者都在毫秒级；SQLite 的优势随规模放大（内存与写放大不增长）。");
            return 0;
        }
        finally
        {
            try { Directory.Delete(root, true); } catch { }
        }
    }

    private static void Row(string label, double a, double b, string unit)
    {
        var ratio = b > 0 ? a / b : 0;
        var gain = unit == "ms" && ratio > 1 ? $"{ratio:F1}× 快"
                 : unit == "B" && ratio > 1 ? $"省 {100.0 * (a - b) / a:F0}%"
                 : ratio is > 0 and < 1 ? $"{ratio:F2}×" : "—";
        Console.WriteLine($"{label,-22}{a,15:N2} {unit,-1}{b,14:N2} {unit,-1}{gain,11}");
    }

    private sealed record Metrics(
        double InsertTotal, double InsertPerOp, double MutatePerOp,
        double ListPerOp, double UnreadPerOp, double StatsPerOp, double SearchPerOp,
        long Bytes, long Memory, string DbPath, string Detail);

    private static Metrics Measure(string label, AppConfig config, int count, int mutationSamples)
    {
        using var store = config.Storage.Provider == "sqlite"
            ? (IMailStore)new SqliteStore(config)
            : new FileStore(config);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        var before = GC.GetTotalMemory(true);

        // ---- 预生成负载（生成不计入耗时）----
        var payloads = new List<(MailMessage Message, byte[] Raw)>(count);
        for (var i = 0; i < count; i++)
        {
            var raw = Mime.Build(new ComposeRequest(
                $"sender{i % 37}@example.com", $"发件人 {i % 37}",
                new[] { config.AdminEmail }, [],
                $"基准测试邮件 #{i}：包含中文主题与正文",
                string.Join("\r\n", Enumerable.Repeat($"这是第 {i} 封测试邮件的正文内容，用于测量存储后端的写入与查询开销。", 12))),
                config);
            var parsed = Mime.Parse(raw);
            var message = new MailMessage
            {
                OwnerEmail = config.AdminEmail,
                Folder = i % 5 == 0 ? "sent" : "inbox",
                From = parsed.From,
                To = parsed.To,
                Subject = parsed.Subject,
                Text = parsed.Text,
                Html = parsed.Html,
                MessageId = parsed.MessageId,
                Date = DateTimeOffset.UtcNow.AddSeconds(-i),
                ReceivedAt = DateTimeOffset.UtcNow,
                Unread = true,
                DeliveryStatus = "received",
            };
            payloads.Add((message, raw));
        }

        // ---- 1) 入库 ----
        var sw = Stopwatch.StartNew();
        foreach (var (message, raw) in payloads) store.SaveMessage(message, raw);
        sw.Stop();
        var insertTotal = sw.Elapsed.TotalMilliseconds;
        var insertPerOp = insertTotal / count;

        // ---- 2) 单条改动（标记已读）----
        var sample = payloads.Take(mutationSamples).Select(p => p.Message.Id).ToArray();
        sw.Restart();
        foreach (var id in sample) store.MarkRead(config.AdminEmail, id, true);
        sw.Stop();
        var mutatePerOp = sw.Elapsed.TotalMilliseconds / sample.Length;

        // ---- 3) 收件箱首页（与 API /api/messages 的真实路径一致：分页）----
        sw.Restart();
        for (var i = 0; i < 10; i++) store.ListMessagesPage(config.AdminEmail, "inbox", "", false, false, 50, 0);
        sw.Stop();
        var listPerOp = sw.Elapsed.TotalMilliseconds / 10;

        // ---- 4) 未读数 ----
        sw.Restart();
        for (var i = 0; i < 20; i++) store.CountUnseen(config.AdminEmail, "inbox");
        sw.Stop();
        var unreadPerOp = sw.Elapsed.TotalMilliseconds / 20;

        // ---- 5) 统计 ----
        sw.Restart();
        for (var i = 0; i < 20; i++) store.Stats(config.AdminEmail);
        sw.Stop();
        var statsPerOp = sw.Elapsed.TotalMilliseconds / 20;

        // ---- 6) 搜索 ----
        sw.Restart();
        for (var i = 0; i < 10; i++) store.ListMessages(config.AdminEmail, "", "第 178 封");
        sw.Stop();
        var searchPerOp = sw.Elapsed.TotalMilliseconds / 10;

        // ---- 7) 空间与内存 ----
        store.Persist();
        long bytes;
        var dbPath = "";
        var breakdown = "";
        if (store is SqliteStore sqlite)
        {
            var report = sqlite.StorageReport();
            bytes = report.DbBytes + report.WalBytes;
            dbPath = report.Database;
            breakdown = $"大对象 {report.BlobStoredBytes:N0} B（由 {report.BlobRawBytes:N0} B 原文压缩而来，{report.BlobGzipped} 个启用压缩）、" +
                        $"正文列 {report.TextBytes:N0} B、空闲页 {report.FreeBytes:N0} B";
        }
        else
        {
            var rawBytes = DirectoryBytes(Path.Combine(config.DataDirectory, "raw"));
            var jsonBytes = new[] { "users.json", "messages.json", "queue.json", "sessions.json" }
                        .Select(f => Path.Combine(config.DataDirectory, f))
                        .Where(File.Exists).Sum(f => new FileInfo(f).Length);
            bytes = jsonBytes + rawBytes + DirectoryBytes(Path.Combine(config.DataDirectory, "attachments"));
            dbPath = config.DataDirectory;
            breakdown = $"JSON {jsonBytes:N0} B + raw 报文 {rawBytes:N0} B";
        }

        GC.Collect();
        GC.WaitForPendingFinalizers();
        var memory = GC.GetTotalMemory(true) - before;

        Console.WriteLine($"{label}：入库 {insertTotal:N0} ms，每封 {insertPerOp:N2} ms，" +
                          $"标记已读 {mutatePerOp:N2} ms/次，占用 {bytes:N0} B");

        return new Metrics(insertTotal, insertPerOp, mutatePerOp, listPerOp, unreadPerOp, statsPerOp, searchPerOp,
            bytes, memory, dbPath, breakdown);
    }

    private static long DirectoryBytes(string path) =>
        Directory.Exists(path) ? Directory.GetFiles(path, "*", SearchOption.AllDirectories).Sum(f => new FileInfo(f).Length) : 0;

    private static AppConfig Clone(AppConfig source, string dataDirectory, string provider, bool fullText) => new()
    {
        Domain = source.Domain,
        Hostname = source.Hostname,
        DataDirectory = dataDirectory,
        AdminEmail = source.AdminEmail,
        AdminPassword = source.AdminPassword,
        DeliveryMode = "direct",
        Dkim = new DkimConfig { Enabled = false },
        Storage = new StorageConfig { Provider = provider, FullTextSearch = fullText },
    };
}
