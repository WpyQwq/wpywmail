using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WpywMail.Native;

/// <summary>
/// 基于文件的存储：users.json / messages.json / queue.json / sessions.json + raw/ 与 attachments/。
/// 单机个人邮箱场景下，这种实现的可靠性与可审计性优于引入数据库依赖。
///
/// 全量写入 + 原子替换（写 .tmp 再 Move），并对所有变更加锁。
///
/// ⚠️ 性能特征：**任何一次改动都会把全部邮件重新序列化并整文件重写**（O(N)），
/// 邮件量上千以后单次「标记已读」也会变得明显昂贵。v2.1 起默认使用
/// <see cref="SqliteStore"/>，本实现保留作为可回滚的后端（Storage.Provider=json）。
/// </summary>
public sealed class FileStore : IMailStore
{
    private readonly object gate = new();
    private readonly JsonSerializerOptions json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string usersPath;
    private readonly string messagesPath;
    private readonly string queuePath;
    private readonly string sessionsPath;
    private readonly string verificationPath;
    private readonly string authEventsPath;
    private readonly string rawDirectory;
    private readonly string attachmentDirectory;
    private readonly AppConfig config;

    private List<MailUser> users = [];
    private List<MailMessage> messages = [];
    private List<QueueItem> queue = [];
    private List<SessionRecord> sessions = [];
    private List<VerificationCode> codes = [];
    private List<AuthEvent> authEvents = [];

    /// <summary>审计保留条数（由 ApiServer 按配置注入）。</summary>
    public int AuditKeep { get; set; } = 2000;

    /// <summary>每次写入都会自增，供长轮询判断「有没有新变化」。</summary>
    private long version;

    public FileStore(AppConfig config)
    {
        this.config = config;
        Directory.CreateDirectory(config.DataDirectory);
        rawDirectory = Path.Combine(config.DataDirectory, "raw");
        attachmentDirectory = Path.Combine(config.DataDirectory, "attachments");
        Directory.CreateDirectory(rawDirectory);
        Directory.CreateDirectory(attachmentDirectory);
        usersPath = Path.Combine(config.DataDirectory, "users.json");
        messagesPath = Path.Combine(config.DataDirectory, "messages.json");
        queuePath = Path.Combine(config.DataDirectory, "queue.json");
        sessionsPath = Path.Combine(config.DataDirectory, "sessions.json");
        verificationPath = Path.Combine(config.DataDirectory, "verification.json");
        authEventsPath = Path.Combine(config.DataDirectory, "auth-events.json");
        Load();
        EnsureAdmin();
    }

    public long Version { get { lock (gate) return version; } }

    private void Load()
    {
        lock (gate)
        {
            users = Read<List<MailUser>>(usersPath) ?? [];
            messages = Read<List<MailMessage>>(messagesPath) ?? [];
            queue = Read<List<QueueItem>>(queuePath) ?? [];
            sessions = Read<List<SessionRecord>>(sessionsPath) ?? [];
            codes = Read<List<VerificationCode>>(verificationPath) ?? [];
            authEvents = Read<List<AuthEvent>>(authEventsPath) ?? [];

            // 上次异常退出时残留的 processing 状态回退成 retry
            foreach (var item in queue.Where(x => x.Status == "processing"))
            {
                item.Status = "retry";
                item.NextAttempt = DateTimeOffset.UtcNow;
            }
            // 过期的会话直接清掉
            var now = DateTimeOffset.UtcNow;
            sessions.RemoveAll(x => x.Expires < now);

            // 给历史邮件补 IMAP UID（同一账号同一文件夹内按时间递增）
            var assigned = false;
            foreach (var group in messages.Where(m => m.Uid == 0).GroupBy(m => (m.OwnerEmail.ToLowerInvariant(), m.Folder.ToLowerInvariant())))
            {
                var uid = messages.Where(m => m.OwnerEmail.Equals(group.Key.Item1, StringComparison.OrdinalIgnoreCase)
                                           && m.Folder.Equals(group.Key.Item2, StringComparison.OrdinalIgnoreCase))
                                  .Select(m => m.Uid).DefaultIfEmpty(0).Max();
                foreach (var message in group.OrderBy(m => m.Date))
                {
                    message.Uid = ++uid;
                    assigned = true;
                }
            }
            if (assigned) Write(messagesPath, messages);

            version++;
        }
    }

    private T? Read<T>(string path)
    {
        if (!File.Exists(path)) return default;
        try { return JsonSerializer.Deserialize<T>(File.ReadAllText(path), json); }
        catch (Exception ex)
        {
            AppLog.Error($"[存储] 读取 {Path.GetFileName(path)} 失败，将从空数据继续：{ex.Message}");
            return default;
        }
    }

    private static void Write<T>(string path, T value)
    {
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(value, new JsonSerializerOptions(JsonSerializerDefaults.Web) { WriteIndented = true }), new UTF8Encoding(false));
        File.Move(temp, path, true);
    }

    private void EnsureAdmin()
    {
        lock (gate)
        {
            var existing = users.FirstOrDefault(x => x.Email.Equals(config.AdminEmail, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                // 配置里的密码变了就同步（方便改密码后重启生效）
                if (!VerifyPassword(config.AdminPassword, existing.PasswordHash, existing.PasswordSalt))
                {
                    existing.PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                    existing.PasswordHash = HashPassword(config.AdminPassword, existing.PasswordSalt);
                    Write(usersPath, users);
                    AppLog.Info($"[存储] 已按 appsettings.json 更新 {existing.Email} 的密码。");
                }
                return;
            }

            var user = new MailUser
            {
                Email = config.AdminEmail.ToLowerInvariant(),
                DisplayName = "Administrator",
                Role = "admin",
                PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            };
            user.PasswordHash = HashPassword(config.AdminPassword, user.PasswordSalt);
            users.Add(user);
            Write(usersPath, users);
            AppLog.Info($"[存储] 已创建管理员邮箱：{user.Email}");
        }
    }

    // ---------------------------------------------------------------- 用户

    public MailUser? FindUser(string email) =>
        users.FirstOrDefault(x => x.Active && x.Email.Equals((email ?? "").Trim(), StringComparison.OrdinalIgnoreCase));

    public MailUser? FindUserAnyState(string email) =>
        users.FirstOrDefault(x => x.Email.Equals((email ?? "").Trim(), StringComparison.OrdinalIgnoreCase));

    public MailUser? Authenticate(string email, string password)
    {
        var user = FindUser(email);
        if (user is null) return null;
        if (!VerifyPassword(password ?? "", user.PasswordHash, user.PasswordSalt)) return null;
        lock (gate)
        {
            user.LastLoginAt = DateTimeOffset.UtcNow;
            Write(usersPath, users);
        }
        return user;
    }

    public bool IsLocalAddress(string email) =>
        FindUser(email) is not null || users.Any(x => x.Email.Equals((email ?? "").Trim(), StringComparison.OrdinalIgnoreCase));

    public IReadOnlyList<MailUser> ListUsers() => users.OrderBy(x => x.Email).ToArray();

    public MailUser CreateUser(string email, string password, string displayName)
    {
        email = (email ?? "").Trim().ToLowerInvariant();
        if (!email.Contains('@')) throw new InvalidOperationException("邮箱地址不合法。");
        if (users.Any(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase))) throw new InvalidOperationException("用户已存在。");
        var user = new MailUser
        {
            Email = email,
            DisplayName = displayName ?? "",
            PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            CreatedAt = DateTimeOffset.UtcNow,
        };
        user.PasswordHash = HashPassword(password, user.PasswordSalt);
        lock (gate) { users.Add(user); Write(usersPath, users); version++; }
        return user;
    }

    /// <summary>用已算好的哈希建号（注册验证通过时用，避免明文密码再走一遍内存）。</summary>
    public MailUser CreateUserWithHash(string email, string passwordHash, string passwordSalt, string displayName, bool active = true)
    {
        email = (email ?? "").Trim().ToLowerInvariant();
        if (!email.Contains('@')) throw new InvalidOperationException("邮箱地址不合法。");
        if (string.IsNullOrEmpty(passwordHash) || string.IsNullOrEmpty(passwordSalt))
            throw new InvalidOperationException("密码哈希不能为空。");
        lock (gate)
        {
            var existing = users.FirstOrDefault(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                // 允许「上次注册没验证完」的账号重新注册：覆盖密码与显示名，保持未激活
                if (existing.Active) throw new InvalidOperationException("用户已存在。");
                existing.DisplayName = displayName ?? existing.DisplayName;
                existing.PasswordHash = passwordHash;
                existing.PasswordSalt = passwordSalt;
                Write(usersPath, users);
                version++;
                return existing;
            }
            var user = new MailUser
            {
                Email = email,
                DisplayName = displayName ?? "",
                PasswordHash = passwordHash,
                PasswordSalt = passwordSalt,
                Active = active,
                CreatedAt = DateTimeOffset.UtcNow,
            };
            users.Add(user);
            Write(usersPath, users);
            version++;
            return user;
        }
    }

    public void ChangePassword(string email, string password)
    {
        lock (gate)
        {
            var user = users.FirstOrDefault(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase))
                       ?? throw new InvalidOperationException("用户不存在。");
            user.PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
            user.PasswordHash = HashPassword(password, user.PasswordSalt);
            Write(usersPath, users);
        }
    }

    public void SetUserActive(string email, bool active)
    {
        lock (gate)
        {
            var user = users.FirstOrDefault(x => x.Email.Equals(email, StringComparison.OrdinalIgnoreCase));
            if (user is null) return;
            user.Active = active;
            Write(usersPath, users);
        }
    }

    public bool DeleteUser(string email)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return false;
        lock (gate)
        {
            var user = users.FirstOrDefault(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase));
            if (user is null) return false;
            users.Remove(user);
            sessions.RemoveAll(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase));
            codes.RemoveAll(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase));
            queue.RemoveAll(x => x.OwnerEmail.Equals(key, StringComparison.OrdinalIgnoreCase));
            Write(usersPath, users);
            Write(sessionsPath, sessions);
            Write(verificationPath, codes);
            Write(queuePath, queue);
            version++;
            return true;
        }
    }

    // ---------------------------------------------------------------- 会话

    public SessionRecord CreateSession(string email, int days)
    {
        var record = new SessionRecord
        {
            Token = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(),
            Email = email,
            Expires = DateTimeOffset.UtcNow.AddDays(Math.Max(1, days)),
        };
        lock (gate)
        {
            sessions.RemoveAll(x => x.Expires < DateTimeOffset.UtcNow);
            sessions.Add(record);
            Write(sessionsPath, sessions);
        }
        return record;
    }

    public SessionRecord? GetSession(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        lock (gate)
        {
            var record = sessions.FirstOrDefault(x => x.Token.Equals(token, StringComparison.Ordinal));
            if (record is null) return null;
            if (record.Expires < DateTimeOffset.UtcNow) { sessions.Remove(record); Write(sessionsPath, sessions); return null; }
            return record;
        }
    }

    public void RemoveSession(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        lock (gate) { sessions.RemoveAll(x => x.Token.Equals(token, StringComparison.Ordinal)); Write(sessionsPath, sessions); }
    }

    public IReadOnlyList<SessionRecord> ListSessions(string email)
    {
        var key = (email ?? "").Trim();
        lock (gate)
        {
            return [.. sessions
                .Where(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase) && x.Expires >= DateTimeOffset.UtcNow)
                .OrderByDescending(x => x.CreatedAt)];
        }
    }

    public int RemoveSessions(string email, string? keepToken)
    {
        var key = (email ?? "").Trim();
        lock (gate)
        {
            var removed = sessions.RemoveAll(x =>
                x.Email.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                (string.IsNullOrWhiteSpace(keepToken) || !x.Token.Equals(keepToken, StringComparison.Ordinal)));
            if (removed > 0) { Write(sessionsPath, sessions); version++; }
            return removed;
        }
    }

    // ---------------------------------------------------------------- 账号体系（注册 / 验证码 / 审计）

    public void UpdateProfile(string email, string displayName)
    {
        lock (gate)
        {
            var user = users.FirstOrDefault(x => x.Email.Equals((email ?? "").Trim(), StringComparison.OrdinalIgnoreCase));
            if (user is null) return;
            user.DisplayName = displayName ?? "";
            Write(usersPath, users);
            version++;
        }
    }

    public void SetLastLogin(string email)
    {
        lock (gate)
        {
            var user = users.FirstOrDefault(x => x.Email.Equals((email ?? "").Trim(), StringComparison.OrdinalIgnoreCase));
            if (user is null) return;
            user.LastLoginAt = DateTimeOffset.UtcNow;
            Write(usersPath, users);
            version++;
        }
    }

    public void SaveVerificationCode(VerificationCode code)
    {
        lock (gate)
        {
            codes.RemoveAll(x => x.Email.Equals(code.Email, StringComparison.OrdinalIgnoreCase) &&
                                 x.Purpose.Equals(code.Purpose, StringComparison.OrdinalIgnoreCase));
            codes.Add(code);
            Write(verificationPath, codes);
            version++;
        }
    }

    public VerificationCode? FindVerificationCode(string email, string purpose)
    {
        var key = (email ?? "").Trim();
        lock (gate)
        {
            return codes.FirstOrDefault(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                                             x.Purpose.Equals(purpose, StringComparison.OrdinalIgnoreCase));
        }
    }

    public int IncrementVerificationAttempts(string email, string purpose)
    {
        var key = (email ?? "").Trim();
        lock (gate)
        {
            var code = codes.FirstOrDefault(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                                                 x.Purpose.Equals(purpose, StringComparison.OrdinalIgnoreCase));
            if (code is null) return 0;
            code.Attempts++;
            Write(verificationPath, codes);
            version++;
            return code.Attempts;
        }
    }

    public void RemoveVerificationCode(string email, string purpose)
    {
        var key = (email ?? "").Trim();
        lock (gate)
        {
            var removed = codes.RemoveAll(x => x.Email.Equals(key, StringComparison.OrdinalIgnoreCase) &&
                                               x.Purpose.Equals(purpose, StringComparison.OrdinalIgnoreCase));
            if (removed > 0) { Write(verificationPath, codes); version++; }
        }
    }

    public void RecordAuthEvent(AuthEvent entry)
    {
        lock (gate)
        {
            authEvents.Add(entry);
            // 超量就按时间淘汰（保留最新 AuditKeep 条）
            if (authEvents.Count > Math.Max(100, AuditKeep))
            {
                authEvents = [.. authEvents.OrderByDescending(x => x.At).Take(Math.Max(100, AuditKeep))];
            }
            Write(authEventsPath, authEvents);
            version++;
        }
    }

    public IReadOnlyList<AuthEvent> ListAuthEvents(string? email, string? ip, string? reason, int limit)
    {
        lock (gate)
        {
            IEnumerable<AuthEvent> q = authEvents;
            if (!string.IsNullOrWhiteSpace(email)) q = q.Where(x => x.Email.Equals(email.Trim(), StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(ip)) q = q.Where(x => x.Ip.Equals(ip.Trim(), StringComparison.Ordinal));
            if (!string.IsNullOrWhiteSpace(reason)) q = q.Where(x => x.Reason.Equals(reason.Trim(), StringComparison.OrdinalIgnoreCase));
            return [.. q.OrderByDescending(x => x.At).Take(Math.Clamp(limit <= 0 ? 200 : limit, 1, 5000))];
        }
    }

    public int CountAuthEvents(string? email, string? ip, string? reason, bool? success, int minutes)
    {
        var since = DateTimeOffset.UtcNow.AddMinutes(-Math.Max(1, minutes));
        lock (gate)
        {
            IEnumerable<AuthEvent> q = authEvents.Where(x => x.At >= since);
            if (!string.IsNullOrWhiteSpace(email)) q = q.Where(x => x.Email.Equals(email.Trim(), StringComparison.OrdinalIgnoreCase));
            if (!string.IsNullOrWhiteSpace(ip)) q = q.Where(x => x.Ip.Equals(ip.Trim(), StringComparison.Ordinal));
            if (!string.IsNullOrWhiteSpace(reason)) q = q.Where(x => x.Reason.Equals(reason.Trim(), StringComparison.OrdinalIgnoreCase));
            if (success.HasValue) q = q.Where(x => x.Success == success.Value);
            return q.Count();
        }
    }

    // ---------------------------------------------------------------- 原始报文与附件

    public string SaveRaw(byte[] raw)
    {
        var name = $"{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}.eml";
        var relative = Path.Combine("raw", name);
        File.WriteAllBytes(Path.Combine(config.DataDirectory, relative), raw);
        return relative;
    }

    public byte[] ReadRaw(string relativePath) => ReadInside(rawDirectory, relativePath);

    public string SaveAttachment(byte[] data, string suggestedName)
    {
        var extension = Path.GetExtension(suggestedName ?? "");
        if (extension.Length > 16) extension = "";
        var name = $"{DateTime.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}{extension}";
        var relative = Path.Combine("attachments", name);
        File.WriteAllBytes(Path.Combine(config.DataDirectory, relative), data);
        return relative;
    }

    public byte[] ReadAttachment(string relativePath) => ReadInside(attachmentDirectory, relativePath);

    private byte[] ReadInside(string allowedDirectory, string relativePath)
    {
        var full = Path.GetFullPath(Path.Combine(config.DataDirectory, relativePath ?? ""));
        var root = Path.GetFullPath(allowedDirectory);
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("非法文件路径。");
        return File.ReadAllBytes(full);
    }

    // ---------------------------------------------------------------- 邮件

    public MailMessage SaveMessage(MailMessage message, byte[]? raw = null)
    {
        if (raw is not null)
        {
            message.RawPath = SaveRaw(raw);
            message.Size = raw.Length;
        }
        lock (gate)
        {
            if (message.Uid == 0) message.Uid = NextUidLocked(message.OwnerEmail, message.Folder);
            messages.Add(message);
            Write(messagesPath, messages);
            version++;
        }
        return message;
    }

    /// <summary>同一账号 + 同一文件夹内的下一个 IMAP UID。</summary>
    private int NextUidLocked(string owner, string folder) =>
        messages.Where(m => m.OwnerEmail.Equals(owner ?? "", StringComparison.OrdinalIgnoreCase)
                         && m.Folder.Equals(folder ?? "", StringComparison.OrdinalIgnoreCase))
                .Select(m => m.Uid).DefaultIfEmpty(0).Max() + 1;

    // ---------------------------------------------------------------- IMAP 支持

    /// <summary>IMAP 用的文件夹列表（固定集合，未使用也返回，便于客户端订阅）。</summary>
    public static readonly string[] ImapFolders = MailFolders.ImapFolders;

    public static string? NormalizeFolder(string name) => MailFolders.Normalize(name);

    /// <summary>按 UID 升序返回某文件夹的邮件（IMAP 要求的稳定顺序）。</summary>
    public IReadOnlyList<MailMessage> ListForImap(string owner, string folder)
    {
        lock (gate)
        {
            return messages
                .Where(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase))
                .Where(x => x.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase))
                .OrderBy(x => x.Uid)
                .ToArray();
        }
    }

    public MailMessage? GetByUid(string owner, string folder, int uid) =>
        ListForImap(owner, folder).FirstOrDefault(x => x.Uid == uid);

    /// <summary>IMAP STORE：设置 \Seen / \Flagged。</summary>
    public bool StoreFlags(string owner, string id, bool? seen, bool? flagged)
    {
        lock (gate)
        {
            var item = GetMessage(owner, id);
            if (item is null) return false;
            if (seen.HasValue) item.Unread = !seen.Value;
            if (flagged.HasValue) item.Starred = flagged.Value;
            Write(messagesPath, messages);
            version++;
            return true;
        }
    }

    /// <summary>IMAP EXPUNGE：inbox 等移入垃圾箱；已在垃圾箱则彻底删除。</summary>
    public bool Expunge(string owner, string id)
    {
        lock (gate)
        {
            var item = GetMessage(owner, id);
            if (item is null) return false;
            if (item.Folder.Equals("trash", StringComparison.OrdinalIgnoreCase))
            {
                messages.Remove(item);
                TryDelete(Path.Combine(config.DataDirectory, item.RawPath));
                foreach (var attachment in item.Attachments) TryDelete(Path.Combine(config.DataDirectory, attachment.StoredAs));
            }
            else
            {
                item.Folder = "trash";
            }
            Write(messagesPath, messages);
            version++;
            return true;
        }
    }

    /// <summary>IMAP APPEND：把客户端上传的报文存入指定文件夹。</summary>
    public MailMessage? Append(string owner, string folder, byte[] raw, bool seen)
    {
        var parsed = Mime.Parse(raw);
        var attachments = new List<Attachment>();
        foreach (var attachment in parsed.Attachments)
        {
            if (attachment.Data.Length == 0) continue;
            attachments.Add(new Attachment
            {
                FileName = attachment.FileName,
                ContentType = attachment.ContentType,
                Size = attachment.Data.Length,
                StoredAs = SaveAttachment(attachment.Data, attachment.FileName),
                ContentId = attachment.ContentId,
                Inline = attachment.Inline,
            });
        }

        return SaveMessage(new MailMessage
        {
            OwnerEmail = owner,
            Folder = folder,
            From = parsed.From,
            To = parsed.To,
            Cc = parsed.Cc,
            Subject = parsed.Subject,
            Text = parsed.Text,
            Html = parsed.Html,
            MessageId = parsed.MessageId,
            InReplyTo = parsed.InReplyTo,
            References = parsed.References,
            Date = parsed.Date ?? DateTimeOffset.UtcNow,
            ReceivedAt = DateTimeOffset.UtcNow,
            Unread = !seen,
            DeliveryStatus = folder == "sent" ? "sent" : "received",
            Attachments = attachments,
        }, raw);
    }

    public int CountUnseen(string owner, string folder) =>
        ListForImap(owner, folder).Count(x => x.Unread);

    public int NextUidFor(string owner, string folder) { lock (gate) return NextUidLocked(owner, folder); }

    /// <summary>把外发报文直接投递给本地收件人（同域发信不必绕 SMTP）。</summary>
    public MailMessage? DeliverLocal(string recipient, byte[] raw, string sender)
    {
        // 必须用 FindUserAnyState：未激活的信箱（注册后待验证）也要能收信，
        // 否则验证码邮件会被静默丢弃。SqliteStore 用的是同一套语义，两个后端契约必须一致。
        // —— 这条不一致就是自检里「验证码邮件真的投进了未激活信箱」抓出来的。
        var user = FindUserAnyState(recipient);
        if (user is null) return null;

        var parsed = Mime.Parse(raw);
        var attachments = new List<Attachment>();
        foreach (var attachment in parsed.Attachments)
        {
            if (attachment.Data.Length == 0) continue;
            attachments.Add(new Attachment
            {
                FileName = attachment.FileName,
                ContentType = attachment.ContentType,
                Size = attachment.Data.Length,
                StoredAs = SaveAttachment(attachment.Data, attachment.FileName),
                ContentId = attachment.ContentId,
                Inline = attachment.Inline,
            });
        }

        return SaveMessage(new MailMessage
        {
            OwnerEmail = user.Email.ToLowerInvariant(),
            Folder = "inbox",
            From = parsed.From.Length > 0 ? parsed.From : sender,
            To = recipient,
            Cc = parsed.Cc,
            Subject = parsed.Subject,
            Text = parsed.Text,
            Html = parsed.Html,
            MessageId = parsed.MessageId,
            InReplyTo = parsed.InReplyTo,
            References = parsed.References,
            Date = parsed.Date ?? DateTimeOffset.UtcNow,
            ReceivedAt = DateTimeOffset.UtcNow,
            DeliveryStatus = "received",
            Unread = true,
            Attachments = attachments,
        }, raw);
    }

    public IReadOnlyList<MailMessage> ListMessages(string owner, string folder, string query)
    {
        query = (query ?? "").Trim();
        lock (gate)
        {
            return messages
                .Where(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase))
                .Where(x => folder.Length == 0 || x.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase))
                .Where(x => query.Length == 0 || $"{x.From} {x.To} {x.Cc} {x.Subject} {x.Text}".Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.Date)
                .ToArray();
        }
    }

    public MailMessage? GetMessage(string owner, string id) =>
        messages.FirstOrDefault(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>分页查询。文件实现只能先全表过滤再切片（这正是它随邮件量变慢的原因）。</summary>
    public (int Total, IReadOnlyList<MailMessage> Messages) ListMessagesPage(
        string owner, string folder, string query, bool unreadOnly, bool starredOnly, int limit, int offset)
    {
        query = (query ?? "").Trim();
        lock (gate)
        {
            var filtered = messages
                .Where(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase))
                .Where(x => folder.Length == 0 || x.Folder.Equals(folder, StringComparison.OrdinalIgnoreCase))
                .Where(x => !unreadOnly || x.Unread)
                .Where(x => !starredOnly || x.Starred)
                .Where(x => query.Length == 0 || $"{x.From} {x.To} {x.Cc} {x.Subject} {x.Text}".Contains(query, StringComparison.OrdinalIgnoreCase))
                .OrderByDescending(x => x.Date)
                .ToArray();
            return (filtered.Length,
                    filtered.Skip(Math.Max(0, offset)).Take(Math.Max(1, limit)).ToArray());
        }
    }

    public MailMessage? GetById(string id) =>
        messages.FirstOrDefault(x => x.Id.Equals(id, StringComparison.OrdinalIgnoreCase));

    /// <summary>迁移用：读出全部邮件与队列（返回的是引用，可就地修改后调用 Persist）。</summary>
    public IReadOnlyList<MailMessage> AllMessages() { lock (gate) return messages.ToArray(); }

    public IReadOnlyList<MailUser> AllUsers() { lock (gate) return users.ToArray(); }

    public void Persist() { lock (gate) { Write(messagesPath, messages); Write(queuePath, queue); Write(usersPath, users); Write(verificationPath, codes); Write(authEventsPath, authEvents); version++; } }

    public bool MarkRead(string owner, string id, bool read)
    {
        lock (gate)
        {
            var item = GetMessage(owner, id);
            if (item is null) return false;
            item.Unread = !read;
            Write(messagesPath, messages);
            return true;
        }
    }

    public bool SetStar(string owner, string id, bool starred)
    {
        lock (gate)
        {
            var item = GetMessage(owner, id);
            if (item is null) return false;
            item.Starred = starred;
            Write(messagesPath, messages);
            return true;
        }
    }

    public bool MoveMessage(string owner, string id, string folder)
    {
        lock (gate)
        {
            var item = GetMessage(owner, id);
            if (item is null) return false;
            item.Folder = folder;
            Write(messagesPath, messages);
            version++;
            return true;
        }
    }

    /// <summary>删除邮件。permanent=false 时只移到垃圾箱。</summary>
    public bool DeleteMessage(string owner, string id, bool permanent)
    {
        lock (gate)
        {
            var item = GetMessage(owner, id);
            if (item is null) return false;
            if (permanent)
            {
                messages.Remove(item);
                TryDelete(Path.Combine(config.DataDirectory, item.RawPath));
                foreach (var attachment in item.Attachments) TryDelete(Path.Combine(config.DataDirectory, attachment.StoredAs));
            }
            else
            {
                item.Folder = "trash";
            }
            Write(messagesPath, messages);
            version++;
            return true;
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    public MailMessage QueueOutbound(string owner, string[] recipients, string subject, string text,
        byte[] raw, string cc = "", string html = "", string inReplyTo = "",
        IReadOnlyList<Attachment>? attachments = null)
    {
        var message = new MailMessage
        {
            OwnerEmail = owner,
            Folder = "sent",
            From = owner,
            To = string.Join(", ", recipients),
            Cc = cc ?? "",
            Subject = subject,
            Text = text,
            Html = html ?? "",
            InReplyTo = inReplyTo ?? "",
            DeliveryStatus = "queued",
            Unread = false,
            Attachments = attachments?.ToList() ?? [],
            Size = raw.Length,
        };
        message.RawPath = SaveRaw(raw);

        lock (gate)
        {
            if (message.Uid == 0) message.Uid = NextUidLocked(owner, "sent");
            messages.Add(message);
            foreach (var recipient in recipients.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                queue.Add(new QueueItem { MessageId = message.Id, OwnerEmail = owner, Recipients = [recipient] });
            }
            Write(messagesPath, messages);
            Write(queuePath, queue);
            version++;
        }
        return message;
    }

    /// <summary>生成一封本地退信（投递彻底失败时发给发件人自己）。</summary>
    public MailMessage CreateBounce(string owner, string originalSubject, string[] recipients, string error, string originalRawPath)
    {
        var subject = $"退信：无法投递到 {string.Join(", ", recipients)}";
        var text = $"""
                  你的邮件未能投递成功。

                  原始主题：{originalSubject}
                  收件人　：{string.Join(", ", recipients)}
                  失败原因：{error}
                  时间　　：{DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}

                  这封退信由 {config.Hostname} 自动生成。原邮件仍保留在「已发送」中，可稍后重试。
                  """;
        var raw = Mime.Build(new ComposeRequest(
            config.AdminEmail, "邮件系统", [owner], [], subject, text), config);

        var message = new MailMessage
        {
            OwnerEmail = owner,
            Folder = "inbox",
            From = $"{config.Hostname} <{config.AdminEmail}>",
            To = owner,
            Subject = subject,
            Text = text,
            DeliveryStatus = "received",
            Unread = true,
        };
        message.RawPath = SaveRaw(raw);
        message.Size = raw.Length;
        lock (gate)
        {
            if (message.Uid == 0) message.Uid = NextUidLocked(owner, "inbox");
            messages.Add(message);
            Write(messagesPath, messages);
            version++;
        }
        return message;
    }

    // ---------------------------------------------------------------- 队列

    public IReadOnlyList<QueueItem> TakeDueQueue(int limit)
    {
        lock (gate)
        {
            var due = queue
                .Where(x => (x.Status is "pending" or "retry") && x.NextAttempt <= DateTimeOffset.UtcNow)
                .OrderBy(x => x.NextAttempt)
                .Take(limit)
                .ToArray();
            foreach (var item in due) item.Status = "processing";
            if (due.Length > 0) Write(queuePath, queue);
            return due;
        }
    }

    public void CompleteQueue(QueueItem item)
    {
        lock (gate)
        {
            item.Status = "sent";
            item.LastAttemptAt = DateTimeOffset.UtcNow;
            item.LastError = "";
            var message = GetById(item.MessageId);
            if (message is not null)
            {
                var remaining = queue.Any(x => x.MessageId == item.MessageId && x.Id != item.Id && x.Status is "pending" or "retry" or "processing");
                message.DeliveryStatus = remaining ? "queued" : "sent";
                if (!remaining) message.LastError = "";
            }
            Write(queuePath, queue);
            Write(messagesPath, messages);
        }
    }

    public void FailQueue(QueueItem item, Exception error, RetryConfig retry, out bool gaveUp)
    {
        lock (gate)
        {
            item.Attempts++;
            item.LastAttemptAt = DateTimeOffset.UtcNow;
            item.LastError = error.Message;
            item.LastCode = error is SmtpDeliveryException smtp ? smtp.Code : 0;

            var permanent = error is SmtpDeliveryException { Permanent: true };
            var maxAttempts = permanent && retry.RetryOnPermanentFailure
                ? Math.Max(1, retry.MaxAttemptsForPermanent)
                : Math.Max(1, retry.MaxAttempts);

            gaveUp = item.Attempts >= maxAttempts;
            item.Status = gaveUp ? "failed" : "retry";

            // 指数退避，带上限
            var delaySeconds = Math.Min(retry.MaxDelaySeconds, retry.InitialDelaySeconds * Math.Pow(2, item.Attempts - 1));
            item.NextAttempt = DateTimeOffset.UtcNow.AddSeconds(delaySeconds);

            var message = GetById(item.MessageId);
            if (message is not null)
            {
                var remaining = queue.Any(x => x.MessageId == item.MessageId && x.Id != item.Id && x.Status is "pending" or "retry" or "processing");
                message.DeliveryStatus = gaveUp && !remaining ? "failed" : "queued";
                message.LastError = error.Message;
            }

            Write(queuePath, queue);
            Write(messagesPath, messages);
        }
    }

    public void RetryQueueItem(string owner, string queueId)
    {
        lock (gate)
        {
            var item = queue.FirstOrDefault(x => x.Id.Equals(queueId, StringComparison.OrdinalIgnoreCase) && x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase));
            if (item is null) return;
            item.Status = "pending";
            item.Attempts = 0;
            item.NextAttempt = DateTimeOffset.UtcNow;
            item.LastError = "";
            Write(queuePath, queue);
        }
    }

    public IReadOnlyList<QueueItem> ListQueue(string owner) =>
        queue.Where(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase))
             .OrderByDescending(x => x.CreatedAt).ToArray();

    public object Stats(string owner)
    {
        lock (gate)
        {
            var mine = messages.Where(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase)).ToArray();
            return new
            {
                inbox = mine.Count(x => x.Folder == "inbox"),
                unread = mine.Count(x => x.Folder == "inbox" && x.Unread),
                starred = mine.Count(x => x.Starred && x.Folder != "trash"),
                drafts = mine.Count(x => x.Folder == "drafts"),
                sent = mine.Count(x => x.Folder == "sent"),
                trash = mine.Count(x => x.Folder == "trash"),
                queue = queue.Count(x => x.OwnerEmail.Equals(owner, StringComparison.OrdinalIgnoreCase) && x.Status is "pending" or "retry" or "processing"),
                failed = mine.Count(x => x.DeliveryStatus == "failed"),
            };
        }
    }

    // ---------------------------------------------------------------- 密码

    private static string HashPassword(string password, string salt) =>
        Convert.ToBase64String(Rfc2898DeriveBytes.Pbkdf2(password, Convert.FromBase64String(salt), 120_000, HashAlgorithmName.SHA256, 32));

    private static bool VerifyPassword(string password, string hash, string salt)
    {
        try
        {
            return CryptographicOperations.FixedTimeEquals(Convert.FromBase64String(hash), Convert.FromBase64String(HashPassword(password, salt)));
        }
        catch { return false; }
    }

    /// <summary>纯文件实现没有需要释放的资源（保留以满足统一接口）。</summary>
    public void Dispose() { }
}
