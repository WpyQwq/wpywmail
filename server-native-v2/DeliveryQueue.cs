namespace WpywMail.Native;

/// <summary>
/// 发件队列。轮询待发任务 → 读取原始报文 →（可选）DKIM 签名 → 投递 → 记录结果。
///
/// 相比 v1 的改进：
///  1. 重试策略可配置（4xx 与 5xx 分开处理，指数退避带上限）；
///  2. DKIM 在投递时签名，因此每次重试都会带上新的时间戳；
///  3. 彻底失败时给发件人投递一封退信（NDR），不再静默丢失。
/// </summary>
public sealed class DeliveryQueue
{
    private readonly AppConfig config;
    private readonly IMailStore store;
    private readonly DirectSmtpDelivery delivery;
    private readonly DkimSigner? signer;

    public DeliveryQueue(AppConfig config, IMailStore store, DkimSigner? signer)
    {
        this.config = config;
        this.store = store;
        this.signer = signer;
        delivery = new DirectSmtpDelivery(config, store);
    }

    public async Task RunAsync(CancellationToken token)
    {
        AppLog.Info($"[发送] 投递模式：{(config.DeliveryMode.Equals("relay", StringComparison.OrdinalIgnoreCase) ? "SMTP 中继" : "按 MX 直接投递")}");
        AppLog.Info($"[发送] 重试策略：最多 {config.Retry.MaxAttempts} 次，初始间隔 {config.Retry.InitialDelaySeconds}s，上限 {config.Retry.MaxDelaySeconds}s" +
                    (config.Retry.RetryOnPermanentFailure ? $"，5xx 也重试 {config.Retry.MaxAttemptsForPermanent} 次" : "，5xx 视为永久失败"));

        while (!token.IsCancellationRequested)
        {
            foreach (var job in store.TakeDueQueue(10))
            {
                if (token.IsCancellationRequested) break;
                await ProcessAsync(job, token);
            }
            try { await Task.Delay(TimeSpan.FromSeconds(5), token); }
            catch (OperationCanceledException) { break; }
        }
    }

    private async Task ProcessAsync(QueueItem job, CancellationToken token)
    {
        var targets = string.Join(", ", job.Recipients);
        try
        {
            var message = store.GetById(job.MessageId) ?? throw new InvalidOperationException("发送队列中的邮件不存在。");

            // 每次投递都重新读取原始报文。
            // 关键顺序：先把行尾规范化为 CRLF，再签名 —— 这样签名覆盖的字节
            // 与传输时写出的字节完全一致（传输阶段只做 dot-stuffing）。
            var raw = SmtpDataEncoder.Normalize(store.ReadRaw(message.RawPath));
            if (signer is not null)
            {
                raw = signer.Sign(raw);
                message.DkimSigned = true;
            }

            await delivery.DeliverAsync(message, job.Recipients, raw, token);
            store.CompleteQueue(job);
            AppLog.Info($"[发送] 投递成功：{targets}（第 {job.Attempts + 1} 次尝试）");
        }
        catch (Exception ex)
        {
            store.FailQueue(job, ex, config.Retry, out var gaveUp);
            if (gaveUp)
            {
                AppLog.Error($"[发送] 已放弃投递：{targets} —— {ex.Message}");
                if (config.Retry.SendBounceNotification) SendBounce(job, ex);
            }
            else
            {
                AppLog.Warn($"[发送] 投递失败（将重试）：{targets} —— {ex.Message}");
            }
        }
    }

    private void SendBounce(QueueItem job, Exception error)
    {
        try
        {
            var message = store.GetById(job.MessageId);
            if (message is null) return;
            store.CreateBounce(job.OwnerEmail, message.Subject, job.Recipients, error.Message, message.RawPath);
            AppLog.Info($"[发送] 已向 {job.OwnerEmail} 投递退信通知。");
        }
        catch (Exception ex)
        {
            AppLog.Error($"[发送] 生成退信失败：{ex.Message}");
        }
    }
}
