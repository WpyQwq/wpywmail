using System.Net;
using System.Net.Mail;

namespace WpywMail.Native;

public sealed class DeliveryQueue
{
    private readonly AppConfig config;
    private readonly FileStore store;
    private readonly DirectSmtpDelivery direct;

    public DeliveryQueue(AppConfig config, FileStore store)
    {
        this.config = config;
        this.store = store;
        direct = new DirectSmtpDelivery(config, store);
    }

    public async Task RunAsync(CancellationToken token)
    {
        AppLog.Info($"[发送] 投递模式：{(config.DeliveryMode.Equals("relay", StringComparison.OrdinalIgnoreCase) ? "SMTP 中继" : "按 MX 直接投递")}");
        while (!token.IsCancellationRequested)
        {
            foreach (var job in store.TakeDueQueue(10))
            {
                try
                {
                    var message = store.GetById(job.MessageId) ?? throw new InvalidOperationException("发送队列中的邮件不存在。");
                    await Deliver(message, job.Recipients, token);
                    store.CompleteQueue(job);
                    AppLog.Info($"[发送] 投递成功：{string.Join(", ", job.Recipients)}");
                }
                catch (Exception ex)
                {
                    store.FailQueue(job, ex);
                    AppLog.Error($"[发送队列] {job.MessageId} → {string.Join(", ", job.Recipients)}：{ex.Message}");
                }
            }
            await Task.Delay(TimeSpan.FromSeconds(5), token).ContinueWith(_ => { });
        }
    }

    private async Task Deliver(MailMessage message, string[] recipients, CancellationToken token)
    {
        if (config.DeliveryMode.Equals("relay", StringComparison.OrdinalIgnoreCase))
        {
            await DeliverThroughRelay(message, recipients, token);
            return;
        }

        await direct.DeliverAsync(message, recipients, token);
    }

    private async Task DeliverThroughRelay(MailMessage message, string[] recipients, CancellationToken token)
    {
        if (string.IsNullOrWhiteSpace(config.Relay.Host)) throw new InvalidOperationException("DeliveryMode=relay 时必须配置 Relay.Host。");
        using var client = new SmtpClient(config.Relay.Host, config.Relay.Port)
        {
            EnableSsl = config.Relay.EnableSsl,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            Timeout = 60_000
        };
        if (!string.IsNullOrWhiteSpace(config.Relay.User)) client.Credentials = new NetworkCredential(config.Relay.User, config.Relay.Password);
        using var mail = new System.Net.Mail.MailMessage
        {
            From = new MailAddress(message.From),
            Subject = message.Subject,
            Body = message.Text,
            BodyEncoding = System.Text.Encoding.UTF8,
            SubjectEncoding = System.Text.Encoding.UTF8
        };
        foreach (var recipient in recipients) mail.To.Add(recipient);
        await client.SendMailAsync(mail, token);
    }
}
