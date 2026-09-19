using System.Text.Json.Serialization;

namespace WpywMail.Native;

public sealed class AppConfig
{
    public string Domain { get; set; } = "wpyw.site";
    public string Hostname { get; set; } = "mail.wpyw.site";
    public string HttpPrefix { get; set; } = "http://127.0.0.1:8787/";
    public int SmtpPort { get; set; } = 25;
    public int SubmissionPort { get; set; } = 587;
    public string DataDirectory { get; set; } = @"H:\MailData";
    public string AdminEmail { get; set; } = "admin@wpyw.site";
    public string AdminPassword { get; set; } = "";
    public string TlsCertificatePath { get; set; } = "";
    public string TlsCertificatePassword { get; set; } = "";
    public string DeliveryMode { get; set; } = "direct";
    public DirectDeliveryConfig DirectDelivery { get; set; } = new();
    public RelayConfig Relay { get; set; } = new();
}

public sealed class DirectDeliveryConfig
{
    public int ConnectionTimeoutSeconds { get; set; } = 30;
    public int CommandTimeoutSeconds { get; set; } = 30;
    public int DnsTimeoutSeconds { get; set; } = 5;
    public bool OpportunisticStartTls { get; set; } = true;
    public bool RequireStartTls { get; set; }
    public string DnsServer { get; set; } = "";
}

public sealed class RelayConfig
{
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string User { get; set; } = "";
    public string Password { get; set; } = "";
    public bool EnableSsl { get; set; } = true;
}

public sealed class MailUser
{
    public string Email { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string PasswordHash { get; set; } = "";
    public string PasswordSalt { get; set; } = "";
    public bool Active { get; set; } = true;
    public string Role { get; set; } = "user";
}

public sealed class MailMessage
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string OwnerEmail { get; set; } = "";
    public string Folder { get; set; } = "inbox";
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    public string Subject { get; set; } = "(无主题)";
    public string Text { get; set; } = "";
    public string RawPath { get; set; } = "";
    public string MessageId { get; set; } = "";
    public DateTimeOffset Date { get; set; } = DateTimeOffset.UtcNow;
    public bool Unread { get; set; } = true;
    public bool Starred { get; set; }
    public string DeliveryStatus { get; set; } = "received";
}

public sealed class QueueItem
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string MessageId { get; set; } = "";
    public string OwnerEmail { get; set; } = "";
    public string[] Recipients { get; set; } = [];
    public int Attempts { get; set; }
    public DateTimeOffset NextAttempt { get; set; } = DateTimeOffset.UtcNow;
    public string Status { get; set; } = "pending";
    public string LastError { get; set; } = "";
}

public sealed record LoginRequest(string Email, string Password);
public sealed record SendRequest(string To, string Subject, string Text);
