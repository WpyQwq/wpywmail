using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WpywMail.Native;

public sealed class FileStore
{
    private readonly object gate = new();
    private readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string usersPath;
    private readonly string messagesPath;
    private readonly string queuePath;
    private readonly string rawDirectory;
    private readonly AppConfig config;
    private List<MailUser> users = [];
    private List<MailMessage> messages = [];
    private List<QueueItem> queue = [];

    public FileStore(AppConfig config)
    {
        this.config = config;
        Directory.CreateDirectory(config.DataDirectory);
        rawDirectory = Path.Combine(config.DataDirectory, "raw");
        Directory.CreateDirectory(rawDirectory);
        usersPath = Path.Combine(config.DataDirectory, "users.json");
        messagesPath = Path.Combine(config.DataDirectory, "messages.json");
        queuePath = Path.Combine(config.DataDirectory, "queue.json");
        Load();
        EnsureAdmin();
    }

    private void Load()
    {
        lock (gate)
        {
            users = Read<List<MailUser>>(usersPath) ?? [];
            messages = Read<List<MailMessage>>(messagesPath) ?? [];
            queue = Read<List<QueueItem>>(queuePath) ?? [];
            foreach (var item in queue.Where(x => x.Status == "processing"))
            {
                item.Status = "retry";
                item.NextAttempt = DateTimeOffset.UtcNow;
            }
        }
    }

    private T? Read<T>(string path)
    {
        if (!File.Exists(path)) return default;
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(path), json); }
        catch { return default; }
    }

    private void Write<T>(string path, T value)
    {
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value, json), Encoding.UTF8);
        File.Move(temp, path, true);
    }

    private void EnsureAdmin()
    {
        if (string.IsNullOrWhiteSpace(config.AdminPassword))
            throw new InvalidOperationException("appsettings.json 中必须设置 AdminPassword。");
        lock (gate)
        {
            if (users.Any(x => x.Email.Equals(config.AdminEmail, StringComparison.OrdinalIgnoreCase))) return;
            users.Add(new MailUser
            {
                Email = config.AdminEmail.ToLowerInvariant(),
                DisplayName = "Administrator",
                Role = "admin",
                PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            });
            users[^1].PasswordHash = HashPassword(config.AdminPassword, users[^1].PasswordSalt);
            Write(usersPath, users);
        }
    }

    public MailUser? FindUser(string email) => users.FirstOrDefault(x => x.Active && x.Email.Equals(email.Trim(), StringComparison.OrdinalIgnoreCase));

    public MailUser? Authenticate(string email, string password)
    {
        var user = FindUser(email);
        return user is not null && VerifyPassword(password, user.PasswordHash, user.PasswordSalt) ? user : null;
    }

    public bool IsLocalAddress(string email) => FindUser(email) is not null;

    public IReadOnlyList<MailUser> ListUsers() => users.Where(x => x.Active).OrderBy(x => x.Email).ToArray();

    public MailUser CreateUser(string email, string password, string displayName)
    {
        email = email.Trim().ToLowerInvariant();
        if (FindUser(email) is not null) throw new InvalidOperationException("用户已存在。");
        var user = new MailUser
        {
            Email = email,
            DisplayName = displayName,
            PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
        };
        user.PasswordHash = HashPassword(password, user.PasswordSalt);
        lock (gate) { users.Add(user); Write(usersPath, users); }
        return user;
    }

    public void ChangePassword(string email, string password)
    {
        lock (gate)
        {
            var user = users.FirstOrDefault(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase)) ?? throw new InvalidOperationException("用户不存在。");
            user.PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            user.PasswordHash = HashPassword(password, user.PasswordSalt);
            Write(usersPath, users);
        }
    }

    public string SaveRaw(byte[] raw)
    {
        var name = $"{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}.eml";
        var relative = Path.Combine("raw", name);
        File.WriteAllBytes(Path.Combine(config.DataDirectory, relative), raw);
        return relative;
    }

    public byte[] ReadRaw(string relativePath)
    {
        var full = Path.GetFullPath(Path.Combine(config.DataDirectory, relativePath));
        if (!full.StartsWith(Path.GetFullPath(rawDirectory), StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("非法文件路径。");
        return File.ReadAllBytes(full);
    }

    public MailMessage SaveMessage(MailMessage message, byte[]? raw = null)
    {
        if (raw is not null) message.RawPath = SaveRaw(raw);
        lock (gate) { messages.Add(message); Write(messagesPath, messages); }
        return message;
    }

    public IReadOnlyList<MailMessage> ListMessages(string owner, string folder, string query)
    {
        query = query.Trim();
        lock (gate)
        {
            return messages.Where(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase))
                .Where(x => x.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase))
                .Where(x => query.Length == 0 || $"{x.From} {x.To} {x.Subject} {x.Text}".Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.Date).ToArray();
        }
    }

    public MailMessage? GetMessage(string owner, string id) => messages.FirstOrDefault(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    public void MarkRead(string owner, string id, bool read = true)
    {
        lock (gate) { var item = GetMessage(owner, id); if (item is null) return; item.Unread = !read; Write(messagesPath, messages); }
    }

    public MailMessage QueueOutbound(string owner, string[] recipients, string subject, string text, byte[] raw)
    {
        var message = new MailMessage { OwnerEmail = owner, Folder = "sent", From = owner, To = string.Join(", ", recipients), Subject = subject, Text = text, DeliveryStatus = "queued", Unread = false };
        message.RawPath = SaveRaw(raw);
        lock (gate)
        {
            messages.Add(message);
            foreach (var recipient in recipients.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                queue.Add(new QueueItem { MessageId = message.Id, OwnerEmail = owner, Recipients = [recipient] });
            }
            Write(messagesPath, messages);
            Write(queuePath, queue);
        }
        return message;
    }

    public IReadOnlyList<QueueItem> TakeDueQueue(int limit)
    {
        lock (gate)
        {
            var due = queue.Where(x => x.Status is "pending" or "retry" && x.NextAttempt <= DateTimeOffset.UtcNow).Take(limit).ToArray();
            foreach (var item in due) item.Status = "processing";
            Write(queuePath, queue);
            return due;
        }
    }

    public MailMessage? GetById(string id) => messages.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    public void CompleteQueue(QueueItem item)
    {
        lock (gate)
        {
            item.Status = "sent";
            var message = GetById(item.MessageId);
            if (message is not null)
            {
                var remaining = queue.Any(x => x.MessageId == item.MessageId && x.Id != item.Id && x.Status is "pending" or "retry" or "processing");
                message.DeliveryStatus = remaining ? "queued" : "sent";
            }
            Write(queuePath, queue); Write(messagesPath, messages);
        }
    }

    public void FailQueue(QueueItem item, Exception error)
    {
        lock (gate)
        {
            item.Attempts++;
            item.LastError = error.Message;
            var permanent = error is SmtpDeliveryException smtp && smtp.Permanent;
            item.Status = permanent || item.Attempts >= 8 ? "failed" : "retry";
            item.NextAttempt = DateTimeOffset.UtcNow.AddMinutes(Math.Min(60, Math.Pow(2, item.Attempts)));
            var message = GetById(item.MessageId);
            if (message is not null)
            {
                var remaining = queue.Any(x => x.MessageId == item.MessageId && x.Id != item.Id && x.Status is "pending" or "retry" or "processing");
                message.DeliveryStatus = item.Status == "failed" && !remaining ? "failed" : "queued";
            }
            Write(queuePath, queue); Write(messagesPath, messages);
        }
    }

    public object Stats(string owner)
    {
        lock (gate)
        {
            return new { inbox = messages.Count(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Folder == "inbox"), unread = messages.Count(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Folder == "inbox" && x.Unread), sent = messages.Count(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Folder == "sent"), queue = queue.Count(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Status is "pending" or "retry" or "processing") };
        }
    }

    private static string HashPassword(string password, string salt) => Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(salt), 120_000, HashAlgorithmName.SHA256, 32));
    private static bool VerifyPassword(string password, string hash, string salt) => CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(hash), Convert.FromBase64String(HashPassword(password, salt)));
}
