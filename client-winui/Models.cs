using System.Text.Json.Serialization;

namespace WpywMail.Client;

public sealed class LoginResponse
{
    public string Token { get; set; } = "";
    public LoginUser User { get; set; } = new();
}

public sealed class LoginUser
{
    public string Email { get; set; } = "";
    public string Role { get; set; } = "user";
    public string Domain { get; set; } = "wpyw.site";
}

public sealed class MessageListResponse
{
    public List<MailSummary> Messages { get; set; } = [];
}

public sealed class MessageDetailResponse
{
    public MailMessage Message { get; set; } = new();
}

public class MailSummary
{
    public string Id { get; set; } = "";
    public string From { get; set; } = "";
    public string To { get; set; } = "";
    public string Subject { get; set; } = "(无主题)";
    public DateTimeOffset Date { get; set; }
    public bool Unread { get; set; }
    public bool Starred { get; set; }
    public string DeliveryStatus { get; set; } = "received";
    public string Preview { get; set; } = "";

    [JsonIgnore]
    public string SenderName => string.IsNullOrWhiteSpace(From) ? "未知发件人" : From.Split('@')[0];

    [JsonIgnore]
    public string Initials => string.Concat(SenderName.Split(['.', '-', '_'], StringSplitOptions.RemoveEmptyEntries).Take(2).Select(x => char.ToUpperInvariant(x[0])));

    [JsonIgnore]
    public string DeliveryStatusLabel => DeliveryStatus switch
    {
        "delivered" => "已投递",
        "failed" => "投递失败",
        "queued" or "pending" or "processing" => "发送中",
        _ => ""
    };

    [JsonIgnore]
    public string DateLabel => Date.Date == DateTimeOffset.Now.Date ? Date.ToLocalTime().ToString("HH:mm") : Date.ToLocalTime().ToString("MM/dd");
}

public sealed class MailMessage : MailSummary
{
    public string OwnerEmail { get; set; } = "";
    public string Folder { get; set; } = "inbox";
    public string Text { get; set; } = "";
    public string MessageId { get; set; } = "";
}

public sealed class AccountStats
{
    public int Inbox { get; set; }
    public int Unread { get; set; }
    public int Sent { get; set; }
    public int Queue { get; set; }
}

public sealed class MeResponse
{
    public LoginUser User { get; set; } = new();
    public AccountStats Stats { get; set; } = new();
}

public sealed class ConfigResponse
{
    public string Domain { get; set; } = "";
    public string Hostname { get; set; } = "";
    public string Account { get; set; } = "";
    public ProtocolConfig Protocols { get; set; } = new();
}

public sealed class ProtocolConfig
{
    public int Smtp { get; set; }
    public int Submission { get; set; }
    public string Api { get; set; } = "";
}
