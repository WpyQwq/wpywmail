using System.Text;

namespace WpywMail.Native;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Contains("--version"))
        {
            Console.WriteLine($"{BuildInfo.Product} {BuildInfo.Version}");
            return 0;
        }
        if (args.Contains("--selftest"))
        {
            return SelfTest.Run();
        }

        var settingsPath = Path.Combine(AppContext.BaseDirectory, "appsettings.json");
        if (!File.Exists(settingsPath))
        {
            Console.Error.WriteLine($"未找到 {settingsPath}，请复制 appsettings.example.json 并填写。");
            return 2;
        }

        AppConfig config;
        try
        {
            config = System.Text.Json.JsonSerializer.Deserialize<AppConfig>(
                         await File.ReadAllTextAsync(settingsPath),
                         new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web))
                     ?? throw new InvalidOperationException("appsettings.json 解析结果为空。");
            config.Validate();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"配置错误：{ex.Message}");
            return 3;
        }

        if (args.Contains("--check-config"))
        {
            Console.WriteLine("配置校验通过。");
            Console.WriteLine($"  域名      ：{config.Domain}");
            Console.WriteLine($"  主机名    ：{config.Hostname}");
            Console.WriteLine($"  管理员    ：{config.AdminEmail}");
            Console.WriteLine($"  数据目录  ：{config.DataDirectory}");
            Console.WriteLine($"  收信/发信 ：{config.SmtpPort} / {config.SubmissionPort}");
            Console.WriteLine($"  投递模式  ：{config.DeliveryMode}");
            Console.WriteLine($"  存储后端  ：{config.Storage.Provider}" +
                              (config.Storage.Provider.Equals("sqlite", StringComparison.OrdinalIgnoreCase)
                                  ? $"（{Path.Combine(config.DataDirectory, "wpywmail.db")}）" : "（JSON 文件）"));
            Console.WriteLine($"  DKIM      ：{(config.Dkim.Enabled ? $"启用（选择器 {config.Dkim.Selector}）" : "未启用")}");

            // 账号策略：这里必须把「本机托管地址免验证」的原因写清楚 ——
            // 否则运维看到 RequireEmailVerification=true 却收不到验证码会一头雾水。
            var acc = config.Accounts;
            var domains = acc.EffectiveDomains(config.Domain);
            var allHosted = domains.Length > 0
                && domains.All(d => d.Equals(config.Domain, StringComparison.OrdinalIgnoreCase));
            var svc = AccountService.IsHostedDomain;
            var hostedDomains = domains.Where(d => svc("x@" + d, config.Domain, config.Hostname)).ToArray();
            Console.WriteLine($"  自助注册  ：{acc.Registration}" +
                              (acc.Registration.Equals("invite", StringComparison.OrdinalIgnoreCase) ? "（需邀请码）" : "")
                              + $"，允许域名：{string.Join(" / ", domains)}");
            Console.WriteLine($"  邮箱验证  ：{(acc.RequireEmailVerification ? "要求" : "不要求")}"
                              + (acc.RequireEmailVerification && allHosted
                                  ? " —— 【注意】允许的域名都由本机托管：验证码邮件投进的正是「验证通过前登录不了」的信箱，"
                                    + "已对这些地址自动跳过验证（授权凭据是邀请码）。要让邮箱验证生效，请把 AllowedDomains 改成托管在别处的域名。"
                                  : acc.RequireEmailVerification && hostedDomains.Length > 0
                                      ? $" —— 其中 {string.Join(" / ", hostedDomains)} 由本机托管，这些地址注册时免验证码直接开通"
                                      : ""));
            return 0;
        }

        // 机器可读地输出 DKIM 公钥记录，供部署脚本写入 DNS。
        // 这一模式必须保持 stdout 干净（只输出 KEY=VALUE），因此关闭控制台日志。
        if (args.Contains("--dkim-dns"))
        {
            AppLog.Configure(config, enableConsole: false);
            var dnsSigner = DkimSigner.Create(config);
            if (dnsSigner is null)
            {
                Console.Error.WriteLine("DKIM 未启用或初始化失败（检查 Dkim.Enabled）。");
                return 4;
            }
            Console.WriteLine("NAME=" + dnsSigner.RecordName);
            Console.WriteLine("VALUE=" + dnsSigner.RecordValue);
            Console.WriteLine("DMARC_NAME=_dmarc." + config.Domain);
            Console.WriteLine("DMARC_VALUE=v=DMARC1; p=none; rua=mailto:" + config.AdminEmail);
            return 0;
        }

        AppLog.Configure(config);

        // 彻底删除账号（管理员维护命令）。会先逐封永久删除该账号的邮件（顺带回收大对象），
        // 再删用户行、会话、验证码与出站队列；审计保留，并写一条 account-purged。
        if (args.Contains("--purge-user"))
        {
            var index = Array.IndexOf(args, "--purge-user");
            var target = index >= 0 && index + 1 < args.Length ? args[index + 1] : "";
            if (string.IsNullOrWhiteSpace(target) || !target.Contains('@'))
            {
                Console.Error.WriteLine("用法：--purge-user <email>（例如 --purge-user spam@wpy.email）");
                return 2;
            }
            using var purgeStore = CreateStore(config);
            var existing = purgeStore.FindUserAnyState(target);
            if (existing is null)
            {
                Console.Error.WriteLine($"找不到账号：{target}");
                return 1;
            }
            var mails = purgeStore.ListMessages(existing.Email, "", "");
            foreach (var mail in mails) purgeStore.DeleteMessage(existing.Email, mail.Id, permanent: true);
            var removed = purgeStore.DeleteUser(existing.Email);
            purgeStore.RecordAuthEvent(new AuthEvent
            {
                Email = existing.Email,
                Ip = "local",
                Reason = "account-purged",
                Success = true,
                Detail = $"邮件 {mails.Count} 封已永久删除（active={existing.Active}，命令 --purge-user）",
            });
            purgeStore.Persist();
            Console.WriteLine(removed
                ? $"已彻底删除账号 {existing.Email}：邮件 {mails.Count} 封、会话/验证码/队列一并清除（审计保留）"
                : $"删除失败：{target}");
            return removed ? 0 : 1;
        }

        // 对**已收到的真实邮件**做 DKIM 验签（走真实 DNS 取发件域公钥）。
        // 用途：① 检验验签实现是否真的对（真邮件是外部签名器签的，自己造的签名骗不过它）；
        //       ② 运维排查「这封信到底是不是伪造的」。SPF 需要收信当时的来源 IP，历史邮件没有，故只做 DKIM。
        if (args.Contains("--verify-inbound"))
        {
            var index = Array.IndexOf(args, "--verify-inbound");
            var limit = index >= 0 && index + 1 < args.Length && int.TryParse(args[index + 1], out var parsed) ? parsed : 25;
            using var verifyStore = CreateStore(config);
            var dns = new UdpDnsLookup(config);
            var all = verifyStore.AllMessages().OrderByDescending(m => m.ReceivedAt > m.Date ? m.ReceivedAt : m.Date).Take(Math.Max(1, limit)).ToList();
            Console.WriteLine($"检查最近 {all.Count} 封已收邮件的 DKIM 签名（真实 DNS）：");
            int signed = 0, passed = 0, failed = 0, unsigned = 0;
            foreach (var message in all)
            {
                byte[] raw;
                try { raw = verifyStore.ReadRaw(message.RawPath); }
                catch { continue; }
                var results = DkimVerifier.VerifyAllAsync(raw, dns, CancellationToken.None).GetAwaiter().GetResult();
                if (results.Count == 0) { unsigned++; continue; }
                signed++;
                var ok = results.Any(r => r.Outcome == "pass");
                if (ok) passed++; else failed++;
                var head = $"[{(ok ? "通过" : results.Any(r => r.Outcome == "temperror") ? "查询失败" : "不通过")}]";
                Console.WriteLine($"{head} {message.From,-38} {message.Subject[..Math.Min(38, message.Subject.Length)]}");
                foreach (var r in results)
                    Console.WriteLine($"        d={r.Domain} s={r.Selector} → {r.Outcome}：{r.Detail}");
            }
            Console.WriteLine();
            Console.WriteLine($"合计：带签名 {signed} 封（通过 {passed} / 不通过 {failed}），无签名 {unsigned} 封。");
            return failed == 0 ? 0 : 1;
        }

        if (args.Contains("--migrate"))        {
            using var migrationStore = new FileStore(config);
            return Migration.Run(config, migrationStore);
        }

        // ---------------- 存储后端维护命令 ----------------
        if (args.Contains("--migrate-to-sqlite"))
            return StorageMigration.ToSqlite(config, deleteSourceFiles: args.Contains("--delete-source"));

        if (args.Contains("--migrate-to-json"))
            return StorageMigration.ToJson(config);

        if (args.Contains("--storage-status"))
            return StorageMigration.Status(config);

        if (args.Contains("--compact"))
            return StorageMigration.Compact(config);

        if (args.Contains("--vacuum"))
            return StorageMigration.Vacuum(config);

        if (args.Contains("--bench-store"))
        {
            var count = args.Select(a => int.TryParse(a, out var n) ? n : 0).FirstOrDefault(n => n > 0);
            return StorageBench.Run(config, count > 0 ? count : 400, mutationSamples: 150);
        }

        // 任何未捕获异常都记录后再退出，避免静默消失
        AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            AppLog.Error($"[致命] 未处理异常：{(e.ExceptionObject as Exception)?.Message ?? e.ExceptionObject?.ToString()}");
        TaskScheduler.UnobservedTaskException += (_, e) =>
        {
            AppLog.Error($"[致命] 未观察的任务异常：{e.Exception.Message}");
            e.SetObserved();
        };

        var store = CreateStore(config);
        var signer = DkimSigner.Create(config);

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            AppLog.Info("收到退出信号，正在停止……");
            cancellation.Cancel();
        };

        AppLog.Info($"中文邮箱服务正在启动，域名：{config.Domain}，主机名：{config.Hostname}，版本：{BuildInfo.Version}");
        if (!config.Dkim.Enabled)
            AppLog.Warn("[DKIM] 未启用签名。建议开启并配置 DNS 记录，否则外发邮件容易被判为垃圾邮件。");

        var api = new ApiServer(config, store);
        var smtp = new SmtpServer(config, store);
        var queue = new DeliveryQueue(config, store, signer);
        var imap = new ImapServer(config, store);

        if (config.Imap.Enabled)
            AppLog.Info($"[IMAP] 已启用：明文/STARTTLS 端口 {config.Imap.Port}，隐式 TLS 端口 {config.Imap.TlsPort}，" +
                        $"登录要求 TLS={config.Imap.RequireTlsForLogin}");

        try
        {
            await Task.WhenAll(
                api.RunAsync(cancellation.Token),
                smtp.RunAsync(cancellation.Token),
                queue.RunAsync(cancellation.Token),
                imap.RunAsync(cancellation.Token));
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            AppLog.Error($"[致命] 服务异常退出：{ex}");
            return 1;
        }

        AppLog.Info("服务已停止。");
        store.Dispose();
        return 0;
    }

    /// <summary>按 Storage.Provider 创建存储后端。sqlite 为默认。</summary>
    public static IMailStore CreateStore(AppConfig config) =>
        config.Storage.Provider.Equals("json", StringComparison.OrdinalIgnoreCase)
            ? new FileStore(config)
            : new SqliteStore(config);
}
