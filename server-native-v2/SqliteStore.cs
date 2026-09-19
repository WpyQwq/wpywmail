using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Data.Sqlite;

namespace WpywMail.Native;

/// <summary>
/// SQLite 存储后端：邮件元数据、用户、会话、出站队列全部进库（带索引与事务），
/// 原始报文（.eml）与附件仍以文件形式存放在 DataDirectory 下。
///
/// 相比 <see cref="FileStore"/> 的关键差别：
///   1. 单条记录的改动只写单行（UPDATE），不再把整个邮箱重新序列化 → 去掉 O(N) 放大；
///   2. UID 分配是 MAX(uid)+1 的索引查询，不再扫描全部邮件；
///   3. 列表/未读数/统计走索引，搜索限定在该账号范围内；
///   4. 事务保证崩溃时不会写坏索引文件（JSON 实现靠 .tmp + Move 兜底，但没有跨文件一致性）；
///   5. WAL 模式：读写不互相阻塞。
/// </summary>
public sealed class SqliteStore : IMailStore, IDisposable
{
    private readonly object gate = new();
    private readonly SqliteConnection connection;
    private readonly string rawDirectory;
    private readonly string attachmentDirectory;
    private readonly AppConfig config;
    private long version;

    public string DatabasePath { get; }

    public SqliteStore(AppConfig config)
    {
        this.config = config;
        Directory.CreateDirectory(config.DataDirectory);
        rawDirectory = Path.Combine(config.DataDirectory, "raw");
        attachmentDirectory = Path.Combine(config.DataDirectory, "attachments");
        Directory.CreateDirectory(rawDirectory);
        Directory.CreateDirectory(attachmentDirectory);

        DatabasePath = string.IsNullOrWhiteSpace(config.Storage.DatabasePath)
            ? Path.Combine(config.DataDirectory, "wpywmail.db")
            : config.Storage.DatabasePath;
        Directory.CreateDirectory(Path.GetDirectoryName(DatabasePath)!);

        connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Private,
            Pooling = false,
        }.ToString());
        connection.Open();

        Execute("PRAGMA journal_mode=WAL;");
        Execute("PRAGMA synchronous=NORMAL;");
        Execute("PRAGMA foreign_keys=ON;");
        Execute("PRAGMA busy_timeout=5000;");
        if (config.Storage.WalAutoCheckpointPages > 0)
            Execute($"PRAGMA wal_autocheckpoint={config.Storage.WalAutoCheckpointPages};");

        CreateSchema();
        SetupFullTextSearch();
        Recover();
        EnsureAdmin();
        version = ReadMetaLong("version");
        AppLog.Info($"[存储] SQLite 已打开：{DatabasePath}（v{version}）");
    }

    // ---------------------------------------------------------------- 基础

    private void Execute(string sql)
    {
        lock (gate)
        {
            using var cmd = connection.CreateCommand();
            cmd.CommandText = sql;
            cmd.ExecuteNonQuery();
        }
    }

    private static SqliteCommand Cmd(SqliteConnection conn, string sql, params (string Name, object? Value)[] args)
    {
        var cmd = conn.CreateCommand();
        cmd.CommandText = sql;
        foreach (var (name, value) in args) cmd.Parameters.AddWithValue(name, value ?? DBNull.Value);
        return cmd;
    }

    private void Mutate(string sql, params (string Name, object? Value)[] args)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection, sql, args);
            cmd.ExecuteNonQuery();
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
        }
    }

    private T Scalar<T>(string sql, T fallback, params (string Name, object? Value)[] args)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection, sql, args);
            var value = cmd.ExecuteScalar();
            if (value is null || value is DBNull) return fallback;
            try { return (T)Convert.ChangeType(value, typeof(T), CultureInfo.InvariantCulture); }
            catch { return fallback; }
        }
    }

    private static string Ts(DateTimeOffset value) => value.ToUniversalTime().ToString("o", CultureInfo.InvariantCulture);

    private static DateTimeOffset ParseTs(object? value, DateTimeOffset fallback) =>
        value is string text && DateTimeOffset.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind, out var parsed)
            ? parsed
            : fallback;

    private long ReadMetaLong(string key) => Scalar($"SELECT value FROM meta WHERE key=@k", 0L, ("@k", key));

    private void WriteMetaLocked(string key, string value)
    {
        using var cmd = Cmd(connection,
            "INSERT INTO meta(key,value) VALUES(@k,@v) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            ("@k", key), ("@v", value));
        cmd.ExecuteNonQuery();
    }

    private void CreateSchema()
    {
        Execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key   TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                email         TEXT PRIMARY KEY COLLATE NOCASE,
                display_name  TEXT NOT NULL DEFAULT '',
                role          TEXT NOT NULL DEFAULT 'user',
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                active        INTEGER NOT NULL DEFAULT 1,
                created_at    TEXT NOT NULL,
                last_login_at TEXT NULL
            );
            CREATE TABLE IF NOT EXISTS messages (
                id              TEXT PRIMARY KEY,
                owner_email     TEXT NOT NULL COLLATE NOCASE,
                folder          TEXT NOT NULL COLLATE NOCASE,
                uid             INTEGER NOT NULL DEFAULT 0,
                from_addr       TEXT NOT NULL DEFAULT '',
                to_addr         TEXT NOT NULL DEFAULT '',
                cc_addr         TEXT NOT NULL DEFAULT '',
                subject         TEXT NOT NULL DEFAULT '',
                text_body       TEXT NOT NULL DEFAULT '',
                html_body       TEXT NOT NULL DEFAULT '',
                raw_path        TEXT NOT NULL DEFAULT '',
                message_id      TEXT NOT NULL DEFAULT '',
                in_reply_to     TEXT NOT NULL DEFAULT '',
                refs            TEXT NOT NULL DEFAULT '',
                date_utc        TEXT NOT NULL,
                received_at     TEXT NOT NULL,
                unread          INTEGER NOT NULL DEFAULT 1,
                starred         INTEGER NOT NULL DEFAULT 0,
                delivery_status TEXT NOT NULL DEFAULT 'received',
                last_error      TEXT NOT NULL DEFAULT '',
                size            INTEGER NOT NULL DEFAULT 0,
                dkim_signed     INTEGER NOT NULL DEFAULT 0
            );
            CREATE UNIQUE INDEX IF NOT EXISTS ux_messages_owner_folder_uid ON messages(owner_email, folder, uid);
            CREATE INDEX IF NOT EXISTS ix_messages_owner_folder_date ON messages(owner_email, folder, date_utc DESC);
            CREATE INDEX IF NOT EXISTS ix_messages_owner_unread      ON messages(owner_email, folder, unread);
            CREATE INDEX IF NOT EXISTS ix_messages_owner_starred     ON messages(owner_email, starred);
            CREATE INDEX IF NOT EXISTS ix_messages_owner_status      ON messages(owner_email, delivery_status);
            -- 只建有查询真的会用的索引：message_id / raw_path 当前没有任何 SQL 按它们检索，
            -- 建了只会白占空间（本机磁盘紧张），需要时再加。
            CREATE TABLE IF NOT EXISTS attachments (
                message_id   TEXT NOT NULL REFERENCES messages(id) ON DELETE CASCADE,
                position     INTEGER NOT NULL,
                file_name    TEXT NOT NULL DEFAULT '',
                content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
                size         INTEGER NOT NULL DEFAULT 0,
                stored_as    TEXT NOT NULL DEFAULT '',
                content_id   TEXT NOT NULL DEFAULT '',
                inline       INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (message_id, position)
            );
            CREATE INDEX IF NOT EXISTS ix_attachments_stored_as ON attachments(stored_as);
            CREATE TABLE IF NOT EXISTS queue (
                id              TEXT PRIMARY KEY,
                message_id      TEXT NOT NULL DEFAULT '',
                owner_email     TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
                recipients      TEXT NOT NULL DEFAULT '[]',
                attempts        INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT NOT NULL,
                next_attempt    TEXT NOT NULL,
                last_attempt_at TEXT NULL,
                status          TEXT NOT NULL DEFAULT 'pending',
                last_error      TEXT NOT NULL DEFAULT '',
                last_code       INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS ix_queue_due     ON queue(status, next_attempt);
            CREATE INDEX IF NOT EXISTS ix_queue_owner   ON queue(owner_email);
            CREATE INDEX IF NOT EXISTS ix_queue_message ON queue(message_id);
            CREATE TABLE IF NOT EXISTS sessions (
                token      TEXT PRIMARY KEY,
                email      TEXT NOT NULL COLLATE NOCASE,
                expires    TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_sessions_expires ON sessions(expires);
            -- 账号体系：邮箱验证码（只存哈希）与认证审计
            CREATE TABLE IF NOT EXISTS verification_codes (
                email      TEXT NOT NULL COLLATE NOCASE,
                purpose    TEXT NOT NULL,
                code_hash  TEXT NOT NULL,
                salt       TEXT NOT NULL,
                payload    TEXT NOT NULL DEFAULT '',
                expires_at TEXT NOT NULL,
                attempts   INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                sent_at    TEXT,
                PRIMARY KEY (email, purpose)
            );
            CREATE TABLE IF NOT EXISTS auth_events (
                id         TEXT PRIMARY KEY,
                email      TEXT NOT NULL DEFAULT '' COLLATE NOCASE,
                ip         TEXT NOT NULL DEFAULT '',
                reason     TEXT NOT NULL DEFAULT '',
                success    INTEGER NOT NULL DEFAULT 0,
                detail     TEXT NOT NULL DEFAULT '',
                user_agent TEXT NOT NULL DEFAULT '',
                at         TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS ix_auth_events_at     ON auth_events(at DESC);
            CREATE INDEX IF NOT EXISTS ix_auth_events_email  ON auth_events(email, reason);
            CREATE INDEX IF NOT EXISTS ix_auth_events_ip     ON auth_events(ip, reason);
            -- 早期版本建过两个没人用的索引，这里幂等清掉（老库也会被回收空间）
            DROP INDEX IF EXISTS ix_messages_message_id;
            DROP INDEX IF EXISTS ix_messages_raw_path;
            -- 报文原文与附件的大对象表：按内容 SHA256 去重，能压就压（省磁盘）。
            -- raw/ 与 attachments/ 目录在 SQLite 模式下**不再写入文件**。
            CREATE TABLE IF NOT EXISTS blobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                sha256      TEXT NOT NULL UNIQUE,
                raw_size    INTEGER NOT NULL,
                stored_size INTEGER NOT NULL,
                gzipped     INTEGER NOT NULL DEFAULT 0,
                data        BLOB NOT NULL,
                created_at  TEXT NOT NULL
            );
            """);
    }

    // ---------------------------------------------------------------- 全文检索（可选）

    private bool fullText;

    /// <summary>
    /// 按配置尝试建立 FTS5(trigram) 全文索引。
    /// 失败（SQLite 未编译 FTS5 / 版本过低）时静默降级为 LIKE 扫描，不影响功能。
    /// </summary>
    private void SetupFullTextSearch()
    {
        if (!config.Storage.FullTextSearch) return;
        try
        {
            Execute("CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(" +
                    "subject, from_addr, to_addr, text_body, " +
                    "content='messages', content_rowid='rowid', tokenize='trigram');");
            Execute("""
                CREATE TRIGGER IF NOT EXISTS messages_fts_ai AFTER INSERT ON messages BEGIN
                  INSERT INTO messages_fts(rowid, subject, from_addr, to_addr, text_body)
                  VALUES (new.rowid, new.subject, new.from_addr, new.to_addr, new.text_body);
                END;
                CREATE TRIGGER IF NOT EXISTS messages_fts_ad AFTER DELETE ON messages BEGIN
                  INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addr, text_body)
                  VALUES ('delete', old.rowid, old.subject, old.from_addr, old.to_addr, old.text_body);
                END;
                CREATE TRIGGER IF NOT EXISTS messages_fts_au AFTER UPDATE ON messages BEGIN
                  INSERT INTO messages_fts(messages_fts, rowid, subject, from_addr, to_addr, text_body)
                  VALUES ('delete', old.rowid, old.subject, old.from_addr, old.to_addr, old.text_body);
                  INSERT INTO messages_fts(rowid, subject, from_addr, to_addr, text_body)
                  VALUES (new.rowid, new.subject, new.from_addr, new.to_addr, new.text_body);
                END;
                """);

            // 索引为空但已有邮件（首次启用）时灌一次；之后靠触发器增量维护
            var indexed = Scalar("SELECT COUNT(1) FROM messages_fts", 0L);
            var stored = Scalar("SELECT COUNT(1) FROM messages", 0L);
            if (indexed == 0 && stored > 0)
            {
                Execute("INSERT INTO messages_fts(messages_fts) VALUES('rebuild');");
                AppLog.Info($"[存储] 已为 {stored} 封历史邮件建立全文索引。");
            }
            fullText = true;
            AppLog.Info("[存储] 全文检索已启用（FTS5 / trigram）。");
        }
        catch (Exception ex)
        {
            fullText = false;
            AppLog.Warn($"[存储] 全文索引不可用，搜索将回退为 LIKE 扫描：{ex.Message}");
        }
    }

    /// <summary>构造 WHERE 子句与参数；搜索在可用时走 FTS，否则回退 LIKE。</summary>
    private (string Where, List<(string Name, object? Value)> Args) BuildFilter(
        string owner, string folder, string query, bool unreadOnly, bool starredOnly)
    {
        var where = "WHERE owner_email=@o";
        var args = new List<(string, object?)> { ("@o", owner ?? "") };
        if (!string.IsNullOrEmpty(folder)) { where += " AND folder=@f"; args.Add(("@f", folder.ToLowerInvariant())); }
        if (unreadOnly) where += " AND unread=1";
        if (starredOnly) where += " AND starred=1";

        query = (query ?? "").Trim();
        if (query.Length > 0)
        {
            if (fullText && query.Length >= 3)
            {
                // trigram 分词器：把查询当整体做子串匹配，需要加引号避免被当成 FTS 语法
                where += " AND rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH @q)";
                args.Add(("@q", "\"" + query.Replace("\"", "\"\"") + "\""));
            }
            else
            {
                where += " AND (from_addr LIKE @q OR to_addr LIKE @q OR cc_addr LIKE @q OR subject LIKE @q OR text_body LIKE @q)";
                args.Add(("@q", "%" + query + "%"));
            }
        }
        return (where, args);
    }

    // ---------------------------------------------------------------- 大对象（报文原文 / 附件）

    private const string BlobPrefix = "db:";

    /// <summary>存入大对象表并返回伪路径 db:&lt;id&gt;；相同内容自动复用（内容寻址去重）。</summary>
    private string SaveBlobLocked(byte[] data)
    {
        var hash = Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();

        using (var probe = Cmd(connection, "SELECT id FROM blobs WHERE sha256=@h", ("@h", hash)))
        {
            var existing = probe.ExecuteScalar();
            if (existing is not null and not DBNull) return BlobPrefix + Convert.ToInt64(existing, CultureInfo.InvariantCulture);
        }

        // 只有压缩确实有收益（≥5%）才存压缩版：JPEG/ZIP 这类已压缩数据不会被白折腾
        var gz = Gzip(data);
        var useGzip = gz.Length < data.Length * 0.95;

        using var cmd = Cmd(connection,
            "INSERT INTO blobs(sha256,raw_size,stored_size,gzipped,data,created_at) VALUES(@h,@r,@s,@g,@d,@c)",
            ("@h", hash), ("@r", data.Length), ("@s", useGzip ? gz.Length : data.Length),
            ("@g", useGzip ? 1 : 0), ("@d", useGzip ? gz : data), ("@c", Ts(DateTimeOffset.UtcNow)));
        cmd.ExecuteNonQuery();

        long id;
        using (var last = Cmd(connection, "SELECT last_insert_rowid()"))
            id = Convert.ToInt64(last.ExecuteScalar(), CultureInfo.InvariantCulture);
        return BlobPrefix + id;
    }

    private byte[] ReadBlobLocked(long id)
    {
        using var cmd = Cmd(connection, "SELECT gzipped, data FROM blobs WHERE id=@id", ("@id", id));
        using var reader = cmd.ExecuteReader();
        if (!reader.Read()) throw new InvalidOperationException($"报文数据不存在（blob {id}）。");
        var gzipped = reader.GetInt64(0) != 0;
        var bytes = (byte[])reader.GetValue(1);
        return gzipped ? Gunzip(bytes) : bytes;
    }

    /// <summary>清理没有任何消息/附件引用的孤儿大对象。</summary>
    private int PurgeOrphanBlobsLocked()
    {
        using var cmd = Cmd(connection,
            "DELETE FROM blobs WHERE id NOT IN (" +
            "  SELECT CAST(substr(raw_path,4) AS INTEGER) FROM messages WHERE raw_path LIKE 'db:%' " +
            "  UNION SELECT CAST(substr(stored_as,4) AS INTEGER) FROM attachments WHERE stored_as LIKE 'db:%')");
        return cmd.ExecuteNonQuery();
    }

    private static byte[] Gzip(byte[] data)
    {
        using var output = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(output, System.IO.Compression.CompressionLevel.Optimal, true))
            gz.Write(data, 0, data.Length);
        return output.ToArray();
    }

    private static byte[] Gunzip(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gz = new System.IO.Compression.GZipStream(input, System.IO.Compression.CompressionMode.Decompress);
        using var output = new MemoryStream();
        gz.CopyTo(output);
        return output.ToArray();
    }

    /// <summary>启动恢复：把上次异常退出留下的 processing 回退成 retry；清掉过期会话；补 UID。</summary>
    private void Recover()
    {
        lock (gate)
        {
            using (var cmd = Cmd(connection, "UPDATE queue SET status='retry', next_attempt=@now WHERE status='processing'",
                       ("@now", Ts(DateTimeOffset.UtcNow))))
                cmd.ExecuteNonQuery();

            using (var cmd = Cmd(connection, "DELETE FROM sessions WHERE expires < @now", ("@now", Ts(DateTimeOffset.UtcNow))))
                cmd.ExecuteNonQuery();

            // 给 uid=0 的历史邮件补号：同一账号 + 同一文件夹按时间递增
            var groups = new List<(string Owner, string Folder)>();
            using (var cmd = Cmd(connection, "SELECT DISTINCT owner_email, folder FROM messages WHERE uid=0"))
            using (var reader = cmd.ExecuteReader())
                while (reader.Read()) groups.Add((reader.GetString(0), reader.GetString(1)));

            foreach (var (owner, folder) in groups)
            {
                var next = Scalar("SELECT COALESCE(MAX(uid),0)+1 FROM messages WHERE owner_email=@o AND folder=@f",
                    1L, ("@o", owner), ("@f", folder));
                var ids = new List<string>();
                using (var cmd = Cmd(connection, "SELECT id FROM messages WHERE owner_email=@o AND folder=@f AND uid=0 ORDER BY date_utc, rowid",
                           ("@o", owner), ("@f", folder)))
                using (var reader = cmd.ExecuteReader())
                    while (reader.Read()) ids.Add(reader.GetString(0));
                foreach (var id in ids)
                {
                    using var cmd = Cmd(connection, "UPDATE messages SET uid=@u WHERE id=@id", ("@u", next++), ("@id", id));
                    cmd.ExecuteNonQuery();
                }
            }
        }
    }

    private void EnsureAdmin()
    {
        var existing = FindUser(config.AdminEmail);
        lock (gate)
        {
            if (existing is not null)
            {
                if (!VerifyPassword(config.AdminPassword, existing.PasswordHash, existing.PasswordSalt))
                {
                    var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
                    using var cmd = Cmd(connection, "UPDATE users SET password_salt=@s, password_hash=@h WHERE email=@e",
                        ("@s", salt), ("@h", HashPassword(config.AdminPassword, salt)), ("@e", existing.Email));
                    cmd.ExecuteNonQuery();
                    AppLog.Info($"[存储] 已按 appsettings.json 更新 {existing.Email} 的密码。");
                }
                return;
            }
        }

        var user = new MailUser
        {
            Email = config.AdminEmail.ToLowerInvariant(),
            DisplayName = "Administrator",
            Role = "admin",
            PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
        };
        user.PasswordHash = HashPassword(config.AdminPassword, user.PasswordSalt);
        lock (gate)
        {
            using var cmd = Cmd(connection,
                "INSERT OR IGNORE INTO users(email,display_name,role,password_hash,password_salt,active,created_at,last_login_at) " +
                "VALUES(@e,@d,@r,@h,@s,1,@c,NULL)",
                ("@e", user.Email), ("@d", user.DisplayName), ("@r", user.Role),
                ("@h", user.PasswordHash), ("@s", user.PasswordSalt), ("@c", Ts(user.CreatedAt)));
            cmd.ExecuteNonQuery();
        }
        AppLog.Info($"[存储] 已创建管理员邮箱：{user.Email}");
    }

    public long Version { get { lock (gate) return version; } }

    // ---------------------------------------------------------------- 用户

    private static MailUser MapUser(SqliteDataReader r) => new()
    {
        Email = r.GetString(0),
        DisplayName = r.GetString(1),
        Role = r.GetString(2),
        PasswordHash = r.GetString(3),
        PasswordSalt = r.GetString(4),
        Active = r.GetInt64(5) != 0,
        CreatedAt = ParseTs(r.IsDBNull(6) ? null : r.GetString(6), DateTimeOffset.UtcNow),
        LastLoginAt = r.IsDBNull(7) ? null : ParseTs(r.GetString(7), DateTimeOffset.UtcNow),
    };

    private const string UserColumns = "email, display_name, role, password_hash, password_salt, active, created_at, last_login_at";

    public MailUser? FindUser(string email)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return null;
        lock (gate)
        {
            using var cmd = Cmd(connection, $"SELECT {UserColumns} FROM users WHERE email=@e AND active=1", ("@e", key));
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? MapUser(reader) : null;
        }
    }

    public MailUser? FindUserAnyState(string email)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return null;
        lock (gate)
        {
            using var cmd = Cmd(connection, $"SELECT {UserColumns} FROM users WHERE email=@e", ("@e", key));
            using var reader = cmd.ExecuteReader();
            return reader.Read() ? MapUser(reader) : null;
        }
    }

    public MailUser? Authenticate(string email, string password)
    {
        var user = FindUser(email);
        if (user is null) return null;
        if (!VerifyPassword(password ?? "", user.PasswordHash, user.PasswordSalt)) return null;
        Mutate("UPDATE users SET last_login_at=@t WHERE email=@e", ("@t", Ts(DateTimeOffset.UtcNow)), ("@e", user.Email));
        user.LastLoginAt = DateTimeOffset.UtcNow;
        return user;
    }

    public bool IsLocalAddress(string email)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return false;
        return Scalar("SELECT COUNT(1) FROM users WHERE email=@e", 0L, ("@e", key)) > 0;
    }

    public IReadOnlyList<MailUser> ListUsers()
    {
        lock (gate)
        {
            var list = new List<MailUser>();
            using var cmd = Cmd(connection, $"SELECT {UserColumns} FROM users ORDER BY email");
            using var reader = cmd.ExecuteReader();
            while (reader.Read()) list.Add(MapUser(reader));
            return list;
        }
    }

    public MailUser CreateUser(string email, string password, string displayName)
    {
        email = (email ?? "").Trim().ToLowerInvariant();
        if (!email.Contains('@')) throw new InvalidOperationException("邮箱地址不合法。");
        if (Scalar("SELECT COUNT(1) FROM users WHERE email=@e", 0L, ("@e", email)) > 0)
            throw new InvalidOperationException("用户已存在。");

        var user = new MailUser
        {
            Email = email,
            DisplayName = displayName ?? "",
            PasswordSalt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16)),
            CreatedAt = DateTimeOffset.UtcNow,
        };
        user.PasswordHash = HashPassword(password, user.PasswordSalt);
        Mutate("INSERT INTO users(email,display_name,role,password_hash,password_salt,active,created_at,last_login_at) " +
               "VALUES(@e,@d,@r,@h,@s,1,@c,NULL)",
            ("@e", user.Email), ("@d", user.DisplayName), ("@r", user.Role),
            ("@h", user.PasswordHash), ("@s", user.PasswordSalt), ("@c", Ts(user.CreatedAt)));
        return user;
    }

    /// <summary>用已算好的哈希建号（注册验证通过时用，避免明文密码再走一遍内存）。</summary>
    public MailUser CreateUserWithHash(string email, string passwordHash, string passwordSalt, string displayName, bool active = true)
    {
        email = (email ?? "").Trim().ToLowerInvariant();
        if (!email.Contains('@')) throw new InvalidOperationException("邮箱地址不合法。");
        if (string.IsNullOrEmpty(passwordHash) || string.IsNullOrEmpty(passwordSalt))
            throw new InvalidOperationException("密码哈希不能为空。");

        var existing = FindUserAnyState(email);
        if (existing is not null)
        {
            // 允许「上次注册没验证完」的账号重新注册：覆盖密码与显示名，保持未激活
            if (existing.Active) throw new InvalidOperationException("用户已存在。");
            Mutate("UPDATE users SET display_name=@d, password_hash=@h, password_salt=@s WHERE email=@e",
                ("@d", displayName ?? existing.DisplayName), ("@h", passwordHash), ("@s", passwordSalt), ("@e", email));
            existing.DisplayName = displayName ?? existing.DisplayName;
            existing.PasswordHash = passwordHash;
            existing.PasswordSalt = passwordSalt;
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
        Mutate("INSERT INTO users(email,display_name,role,password_hash,password_salt,active,created_at,last_login_at) " +
               "VALUES(@e,@d,@r,@h,@s,@a,@c,NULL)",
            ("@e", user.Email), ("@d", user.DisplayName), ("@r", user.Role),
            ("@h", user.PasswordHash), ("@s", user.PasswordSalt), ("@a", user.Active ? 1 : 0),
            ("@c", Ts(user.CreatedAt)));
        return user;
    }

    public void ChangePassword(string email, string password)    {
        var salt = Convert.ToBase64String(RandomNumberGenerator.GetBytes(16));
        var hash = HashPassword(password, salt);
        lock (gate)
        {
            using var cmd = Cmd(connection, "UPDATE users SET password_salt=@s, password_hash=@h WHERE email=@e",
                ("@s", salt), ("@h", hash), ("@e", (email ?? "").Trim()));
            if (cmd.ExecuteNonQuery() == 0) throw new InvalidOperationException("用户不存在。");
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
        }
    }

    public void SetUserActive(string email, bool active) =>
        Mutate("UPDATE users SET active=@a WHERE email=@e", ("@a", active ? 1 : 0), ("@e", (email ?? "").Trim()));

    public bool DeleteUser(string email)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return false;
        if (FindUserAnyState(key) is null) return false;
        RemoveSessions(key, null);
        Mutate("DELETE FROM verification_codes WHERE email=@e", ("@e", key));
        Mutate("DELETE FROM queue WHERE owner_email=@e", ("@e", key));
        Mutate("DELETE FROM users WHERE email=@e", ("@e", key));
        return true;
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
            using (var cmd = Cmd(connection, "DELETE FROM sessions WHERE expires < @now", ("@now", Ts(DateTimeOffset.UtcNow))))
                cmd.ExecuteNonQuery();
            using (var cmd = Cmd(connection, "INSERT INTO sessions(token,email,expires,created_at) VALUES(@t,@e,@x,@c)",
                       ("@t", record.Token), ("@e", record.Email), ("@x", Ts(record.Expires)), ("@c", Ts(record.CreatedAt))))
                cmd.ExecuteNonQuery();
        }
        return record;
    }

    public SessionRecord? GetSession(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        lock (gate)
        {
            using var cmd = Cmd(connection, "SELECT token,email,expires,created_at FROM sessions WHERE token=@t", ("@t", token));
            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;
            var record = new SessionRecord
            {
                Token = reader.GetString(0),
                Email = reader.GetString(1),
                Expires = ParseTs(reader.GetString(2), DateTimeOffset.UtcNow),
                CreatedAt = ParseTs(reader.GetString(3), DateTimeOffset.UtcNow),
            };
            if (record.Expires >= DateTimeOffset.UtcNow) return record;
        }
        RemoveSession(token);
        return null;
    }

    public void RemoveSession(string token)
    {
        if (string.IsNullOrWhiteSpace(token)) return;
        Mutate("DELETE FROM sessions WHERE token=@t", ("@t", token));
    }

    public IReadOnlyList<SessionRecord> ListSessions(string email)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return [];
        lock (gate)
        {
            var list = new List<SessionRecord>();
            using var cmd = Cmd(connection,
                "SELECT token,email,expires,created_at FROM sessions WHERE email=@e AND expires >= @now ORDER BY created_at DESC",
                ("@e", key), ("@now", Ts(DateTimeOffset.UtcNow)));
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new SessionRecord
                {
                    Token = reader.GetString(0),
                    Email = reader.GetString(1),
                    Expires = ParseTs(reader.GetString(2), DateTimeOffset.UtcNow),
                    CreatedAt = ParseTs(reader.GetString(3), DateTimeOffset.UtcNow),
                });
            }
            return list;
        }
    }

    public int RemoveSessions(string email, string? keepToken)
    {
        var key = (email ?? "").Trim();
        if (key.Length == 0) return 0;
        lock (gate)
        {
            using var cmd = string.IsNullOrWhiteSpace(keepToken)
                ? Cmd(connection, "DELETE FROM sessions WHERE email=@e", ("@e", key))
                : Cmd(connection, "DELETE FROM sessions WHERE email=@e AND token<>@t", ("@e", key), ("@t", keepToken));
            var removed = cmd.ExecuteNonQuery();
            if (removed > 0)
            {
                version++;
                WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
            }
            return removed;
        }
    }

    // ---------------------------------------------------------------- 原始报文与附件
    //
    // SQLite 模式下报文原文与附件都存进 blobs 表（gzip + 内容去重），**不再落任何文件**。
    // 对外仍然是「SaveXxx 返回一个相对路径、ReadXxx 按该路径取回」的语义，
    // 只是路径形态变成 db:<id>，上层（API / IMAP / 投递队列）完全不用改。

    public string SaveRaw(byte[] raw)
    {
        lock (gate) return SaveBlobLocked(raw);
    }

    public byte[] ReadRaw(string relativePath)
    {
        if (IsBlobPath(relativePath)) { lock (gate) return ReadBlobLocked(BlobId(relativePath)); }
        return ReadInside(rawDirectory, relativePath);   // 迁移期间仍可能指向老的 raw/*.eml
    }

    public string SaveAttachment(byte[] data, string suggestedName)
    {
        lock (gate) return SaveBlobLocked(data);
    }

    public byte[] ReadAttachment(string relativePath)
    {
        if (IsBlobPath(relativePath)) { lock (gate) return ReadBlobLocked(BlobId(relativePath)); }
        return ReadInside(attachmentDirectory, relativePath);
    }

    private static bool IsBlobPath(string? path) =>
        path is not null && path.StartsWith(BlobPrefix, StringComparison.OrdinalIgnoreCase);

    private static long BlobId(string path) =>
        long.TryParse(path.AsSpan(BlobPrefix.Length), NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
            ? id : throw new InvalidOperationException($"非法的大对象路径：{path}");

    /// <summary>存储占用统计（给 --storage-status / 基准测试用）。</summary>
    public StoreUsage StorageReport()
    {
        lock (gate)
        {
            long ScalarLong(string sql)
            {
                using var cmd = Cmd(connection, sql);
                var value = cmd.ExecuteScalar();
                return value is null or DBNull ? 0 : Convert.ToInt64(value, CultureInfo.InvariantCulture);
            }

            var files = new FileInfo(DatabasePath);
            var wal = new FileInfo(DatabasePath + "-wal");
            var pageSize = ScalarLong("SELECT page_size FROM pragma_page_size()");
            var pageCount = ScalarLong("SELECT page_count FROM pragma_page_count()");
            var freePages = ScalarLong("SELECT freelist_count FROM pragma_freelist_count()");
            return new StoreUsage
            {
                Provider = "sqlite",
                Database = DatabasePath,
                DbBytes = files.Exists ? files.Length : 0,
                WalBytes = wal.Exists ? wal.Length : 0,
                Blobs = ScalarLong("SELECT COUNT(1) FROM blobs"),
                BlobRawBytes = ScalarLong("SELECT COALESCE(SUM(raw_size),0) FROM blobs"),
                BlobStoredBytes = ScalarLong("SELECT COALESCE(SUM(stored_size),0) FROM blobs"),
                BlobGzipped = ScalarLong("SELECT COUNT(1) FROM blobs WHERE gzipped=1"),
                Messages = ScalarLong("SELECT COUNT(1) FROM messages"),
                Orphans = ScalarLong(
                    "SELECT COUNT(1) FROM blobs WHERE id NOT IN (" +
                    "  SELECT CAST(substr(raw_path,4) AS INTEGER) FROM messages WHERE raw_path LIKE 'db:%' " +
                    "  UNION SELECT CAST(substr(stored_as,4) AS INTEGER) FROM attachments WHERE stored_as LIKE 'db:%')"),
                TextBytes = ScalarLong("SELECT COALESCE(SUM(LENGTH(text_body)+LENGTH(html_body)),0) FROM messages"),
                FreeBytes = freePages * pageSize,
                TotalBytes = pageCount * pageSize,
                PageCount = pageCount,
                PageSize = pageSize,
                LargestTextBytes = ScalarLong("SELECT COALESCE(MAX(LENGTH(text_body)+LENGTH(html_body)),0) FROM messages"),
                LargestTextSubject = LargestTextSubjectLocked(),
            };
        }
    }

    /// <summary>删除孤儿大对象，返回删除条数。</summary>
    public int Compact()
    {
        lock (gate) return PurgeOrphanBlobsLocked();
    }

    private string LargestTextSubjectLocked()
    {
        using var cmd = Cmd(connection,
            "SELECT subject FROM messages ORDER BY LENGTH(text_body)+LENGTH(html_body) DESC LIMIT 1");
        var value = cmd.ExecuteScalar();
        return value is null or DBNull ? "" : Convert.ToString(value, CultureInfo.InvariantCulture) ?? "";
    }

    private byte[] ReadInside(string allowedDirectory, string relativePath)
    {
        var full = Path.GetFullPath(Path.Combine(config.DataDirectory, relativePath ?? ""));
        var root = Path.GetFullPath(allowedDirectory);
        if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("非法文件路径。");
        return File.ReadAllBytes(full);
    }

    // ---------------------------------------------------------------- 邮件

    private const string MessageColumns =
        "id, owner_email, folder, uid, from_addr, to_addr, cc_addr, subject, text_body, html_body, raw_path, " +
        "message_id, in_reply_to, refs, date_utc, received_at, unread, starred, delivery_status, last_error, size, dkim_signed";

    private static MailMessage MapMessage(SqliteDataReader r) => new()
    {
        Id = r.GetString(0),
        OwnerEmail = r.GetString(1),
        Folder = r.GetString(2),
        Uid = (int)r.GetInt64(3),
        From = r.GetString(4),
        To = r.GetString(5),
        Cc = r.GetString(6),
        Subject = r.GetString(7),
        Text = r.GetString(8),
        Html = r.GetString(9),
        RawPath = r.GetString(10),
        MessageId = r.GetString(11),
        InReplyTo = r.GetString(12),
        References = r.GetString(13),
        Date = ParseTs(r.GetString(14), DateTimeOffset.UtcNow),
        ReceivedAt = ParseTs(r.GetString(15), DateTimeOffset.UtcNow),
        Unread = r.GetInt64(16) != 0,
        Starred = r.GetInt64(17) != 0,
        DeliveryStatus = r.GetString(18),
        LastError = r.GetString(19),
        Size = r.GetInt64(20),
        DkimSigned = r.GetInt64(21) != 0,
    };

    private int NextUidLocked(string owner, string folder) => (int)Scalar(
        "SELECT COALESCE(MAX(uid),0)+1 FROM messages WHERE owner_email=@o AND folder=@f", 1L,
        ("@o", owner ?? ""), ("@f", folder ?? ""));

    /// <summary>在已持有 gate 的前提下插入一行邮件（含附件）。</summary>
    private void InsertMessageLocked(MailMessage message)
    {
        using var tx = connection.BeginTransaction();
        using (var cmd = Cmd(connection,
            "INSERT INTO messages(" + MessageColumns + ") VALUES(" +
            "@id,@owner,@folder,@uid,@from,@to,@cc,@subject,@text,@html,@raw,@mid,@irt,@refs,@date,@recv,@unread,@starred,@status,@err,@size,@dkim)",
            ("@id", message.Id), ("@owner", message.OwnerEmail.ToLowerInvariant()), ("@folder", message.Folder.ToLowerInvariant()),
            ("@uid", message.Uid), ("@from", message.From ?? ""), ("@to", message.To ?? ""), ("@cc", message.Cc ?? ""),
            ("@subject", message.Subject ?? ""), ("@text", message.Text ?? ""), ("@html", message.Html ?? ""),
            ("@raw", message.RawPath ?? ""), ("@mid", message.MessageId ?? ""), ("@irt", message.InReplyTo ?? ""),
            ("@refs", message.References ?? ""), ("@date", Ts(message.Date)), ("@recv", Ts(message.ReceivedAt)),
            ("@unread", message.Unread ? 1 : 0), ("@starred", message.Starred ? 1 : 0),
            ("@status", message.DeliveryStatus ?? "received"), ("@err", message.LastError ?? ""),
            ("@size", message.Size), ("@dkim", message.DkimSigned ? 1 : 0)))
        {
            cmd.Transaction = tx;
            cmd.ExecuteNonQuery();
        }

        var position = 0;
        foreach (var attachment in message.Attachments)
        {
            using var cmd = Cmd(connection,
                "INSERT INTO attachments(message_id,position,file_name,content_type,size,stored_as,content_id,inline) " +
                "VALUES(@m,@p,@f,@c,@s,@a,@i,@n)",
                ("@m", message.Id), ("@p", position++), ("@f", attachment.FileName ?? ""),
                ("@c", attachment.ContentType ?? "application/octet-stream"), ("@s", attachment.Size),
                ("@a", attachment.StoredAs ?? ""), ("@i", attachment.ContentId ?? ""), ("@n", attachment.Inline ? 1 : 0));
            cmd.Transaction = tx;
            cmd.ExecuteNonQuery();
        }

        tx.Commit();
        version++;
        WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
    }

    public MailMessage SaveMessage(MailMessage message, byte[]? raw = null)
    {
        if (raw is not null)
        {
            message.RawPath = SaveRaw(raw);
            message.Size = raw.Length;
        }
        message.OwnerEmail = (message.OwnerEmail ?? "").ToLowerInvariant();
        message.Folder = (message.Folder ?? "inbox").ToLowerInvariant();
        lock (gate)
        {
            if (message.Uid == 0) message.Uid = NextUidLocked(message.OwnerEmail, message.Folder);
            InsertMessageLocked(message);
        }
        return message;
    }

    private void AttachLocked(IReadOnlyList<MailMessage> messages, Dictionary<string, List<Attachment>> map)
    {
        foreach (var message in messages)
            if (map.TryGetValue(message.Id, out var list)) message.Attachments = list;
    }

    private Dictionary<string, List<Attachment>> AttachmentMapLocked(IEnumerable<string> ids)
    {
        var ids2 = ids.ToArray();
        var map = new Dictionary<string, List<Attachment>>(StringComparer.Ordinal);
        if (ids2.Length == 0) return map;
        foreach (var chunk in ids2.Chunk(400))
        {
            var names = chunk.Select((_, i) => "@p" + i).ToArray();
            var args = chunk.Select((id, i) => ("@p" + i, (object?)id)).ToArray();
            using var cmd = Cmd(connection,
                $"SELECT message_id,file_name,content_type,size,stored_as,content_id,inline FROM attachments " +
                $"WHERE message_id IN ({string.Join(",", names)}) ORDER BY message_id, position", args);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                var key = reader.GetString(0);
                if (!map.TryGetValue(key, out var list)) map[key] = list = [];
                list.Add(new Attachment
                {
                    FileName = reader.GetString(1),
                    ContentType = reader.GetString(2),
                    Size = reader.GetInt64(3),
                    StoredAs = reader.GetString(4),
                    ContentId = reader.GetString(5),
                    Inline = reader.GetInt64(6) != 0,
                });
            }
        }
        return map;
    }

    private List<MailMessage> QueryMessagesLocked(string sql, params (string Name, object? Value)[] args)
    {
        var list = new List<MailMessage>();
        using (var cmd = Cmd(connection, sql, args))
        using (var reader = cmd.ExecuteReader())
            while (reader.Read()) list.Add(MapMessage(reader));
        AttachLocked(list, AttachmentMapLocked(list.Select(m => m.Id)));
        return list;
    }

    public IReadOnlyList<MailMessage> ListMessages(string owner, string folder, string query)
    {
        lock (gate)
        {
            var (where, args) = BuildFilter(owner, folder, query, unreadOnly: false, starredOnly: false);
            return QueryMessagesLocked($"SELECT {MessageColumns} FROM messages {where} ORDER BY date_utc DESC", args.ToArray());
        }
    }

    /// <summary>分页查询：COUNT 与取页都下推到 SQL，附带的条件（未读/星标/搜索）同样在库内完成。</summary>
    public (int Total, IReadOnlyList<MailMessage> Messages) ListMessagesPage(
        string owner, string folder, string query, bool unreadOnly, bool starredOnly, int limit, int offset)
    {
        lock (gate)
        {
            var (where, args) = BuildFilter(owner, folder, query, unreadOnly, starredOnly);

            int total;
            using (var countCmd = Cmd(connection, $"SELECT COUNT(1) FROM messages {where}", args.ToArray()))
                total = Convert.ToInt32(countCmd.ExecuteScalar() ?? 0, CultureInfo.InvariantCulture);

            var pageArgs = new List<(string, object?)>(args)
            {
                ("@limit", Math.Max(1, limit)),
                ("@offset", Math.Max(0, offset)),
            };
            var page = QueryMessagesLocked(
                $"SELECT {MessageColumns} FROM messages {where} ORDER BY date_utc DESC LIMIT @limit OFFSET @offset",
                pageArgs.ToArray());
            return (total, page);
        }
    }

    public MailMessage? GetMessage(string owner, string id)
    {
        lock (gate)
        {
            var list = QueryMessagesLocked(
                $"SELECT {MessageColumns} FROM messages WHERE owner_email=@o AND id=@id", ("@o", owner ?? ""), ("@id", id ?? ""));
            return list.Count > 0 ? list[0] : null;
        }
    }

    public MailMessage? GetById(string id)
    {
        lock (gate)
        {
            var list = QueryMessagesLocked($"SELECT {MessageColumns} FROM messages WHERE id=@id", ("@id", id ?? ""));
            return list.Count > 0 ? list[0] : null;
        }
    }

    public MailMessage? GetByUid(string owner, string folder, int uid)
    {
        lock (gate)
        {
            var list = QueryMessagesLocked(
                $"SELECT {MessageColumns} FROM messages WHERE owner_email=@o AND folder=@f AND uid=@u",
                ("@o", owner ?? ""), ("@f", (folder ?? "").ToLowerInvariant()), ("@u", uid));
            return list.Count > 0 ? list[0] : null;
        }
    }

    public bool MarkRead(string owner, string id, bool read)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection, "UPDATE messages SET unread=@u WHERE owner_email=@o AND id=@id",
                ("@u", read ? 0 : 1), ("@o", owner ?? ""), ("@id", id ?? ""));
            if (cmd.ExecuteNonQuery() == 0) return false;
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
            return true;
        }
    }

    public bool SetStar(string owner, string id, bool starred)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection, "UPDATE messages SET starred=@s WHERE owner_email=@o AND id=@id",
                ("@s", starred ? 1 : 0), ("@o", owner ?? ""), ("@id", id ?? ""));
            if (cmd.ExecuteNonQuery() == 0) return false;
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
            return true;
        }
    }

    public bool MoveMessage(string owner, string id, string folder)
    {
        lock (gate)
        {
            var message = GetMessage(owner, id);
            if (message is null) return false;
            var target = (folder ?? "inbox").ToLowerInvariant();
            var uid = target == message.Folder ? message.Uid : NextUidLocked(message.OwnerEmail, target);
            using var cmd = Cmd(connection, "UPDATE messages SET folder=@f, uid=@u WHERE id=@id",
                ("@f", target), ("@u", uid), ("@id", message.Id));
            cmd.ExecuteNonQuery();
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
            return true;
        }
    }

    public bool DeleteMessage(string owner, string id, bool permanent)
    {
        lock (gate)
        {
            var message = GetMessage(owner, id);
            if (message is null) return false;
            if (permanent) DeleteRowLocked(message);
            else MoveMessage(owner, id, "trash");
            return true;
        }
    }

    private void DeleteRowLocked(MailMessage message)
    {
        using (var cmd = Cmd(connection, "DELETE FROM messages WHERE id=@id", ("@id", message.Id)))
            cmd.ExecuteNonQuery();
        if (!IsBlobPath(message.RawPath)) TryDelete(Path.Combine(config.DataDirectory, message.RawPath));
        foreach (var attachment in message.Attachments)
            if (!IsBlobPath(attachment.StoredAs)) TryDelete(Path.Combine(config.DataDirectory, attachment.StoredAs));
        PurgeOrphanBlobsLocked();
        version++;
        WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
    }

    // ---------------------------------------------------------------- 迁移专用导入
    // 这些方法保留原始字段（密码哈希、UID、队列状态、会话令牌），供 JSON → SQLite 无损迁移使用。

    /// <summary>按原样导入用户（保留既有密码哈希与盐，不重新计算）。</summary>
    public void ImportUser(MailUser user)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection,
                "INSERT OR REPLACE INTO users(email,display_name,role,password_hash,password_salt,active,created_at,last_login_at) " +
                "VALUES(@e,@d,@r,@h,@s,@a,@c,@l)",
                ("@e", (user.Email ?? "").ToLowerInvariant()), ("@d", user.DisplayName ?? ""), ("@r", user.Role ?? "user"),
                ("@h", user.PasswordHash), ("@s", user.PasswordSalt), ("@a", user.Active ? 1 : 0),
                ("@c", Ts(user.CreatedAt)), ("@l", user.LastLoginAt.HasValue ? Ts(user.LastLoginAt.Value) : null));
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>按原样导入队列项（保留状态、重试次数与下次尝试时间）。</summary>
    public void ImportQueueItem(QueueItem item)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection,
                "INSERT OR REPLACE INTO queue(id,message_id,owner_email,recipients,attempts,created_at,next_attempt,last_attempt_at,status,last_error,last_code) " +
                "VALUES(@id,@m,@o,@r,@a,@c,@n,@l,@s,@e,@code)",
                ("@id", item.Id), ("@m", item.MessageId), ("@o", item.OwnerEmail ?? ""),
                ("@r", JsonSerializer.Serialize(item.Recipients ?? [])), ("@a", item.Attempts),
                ("@c", Ts(item.CreatedAt)), ("@n", Ts(item.NextAttempt)),
                ("@l", item.LastAttemptAt.HasValue ? Ts(item.LastAttemptAt.Value) : null),
                ("@s", item.Status ?? "pending"), ("@e", item.LastError ?? ""), ("@code", item.LastCode));
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>按原样导入会话（保留令牌，避免迁移把已登录客户端踢下线）。</summary>
    public void ImportSession(SessionRecord session)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection,
                "INSERT OR REPLACE INTO sessions(token,email,expires,created_at) VALUES(@t,@e,@x,@c)",
                ("@t", session.Token), ("@e", session.Email), ("@x", Ts(session.Expires)), ("@c", Ts(session.CreatedAt)));
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>导出全部大对象（供 SQLite → JSON 反向回滚）。</summary>
    public IReadOnlyList<(long Id, byte[] Data)> ExportBlobs()
    {
        lock (gate)
        {
            var ids = new List<long>();
            using (var cmd = Cmd(connection, "SELECT id FROM blobs ORDER BY id"))
            using (var reader = cmd.ExecuteReader())
                while (reader.Read()) ids.Add(reader.GetInt64(0));
            return ids.Select(id => (id, ReadBlobLocked(id))).ToArray();
        }
    }

    public IReadOnlyList<QueueItem> AllQueueItems()
    {
        lock (gate)
        {
            var list = new List<QueueItem>();
            using var cmd = Cmd(connection, $"SELECT {QueueColumns} FROM queue");
            using var reader = cmd.ExecuteReader();
            while (reader.Read()) list.Add(MapQueue(reader));
            return list;
        }
    }

    public IReadOnlyList<SessionRecord> AllSessions()
    {
        lock (gate)
        {
            var list = new List<SessionRecord>();
            using var cmd = Cmd(connection, "SELECT token,email,expires,created_at FROM sessions");
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
                list.Add(new SessionRecord
                {
                    Token = reader.GetString(0),
                    Email = reader.GetString(1),
                        Expires = ParseTs(reader.GetString(2), DateTimeOffset.UtcNow),
                        CreatedAt = ParseTs(reader.GetString(3), DateTimeOffset.UtcNow),
                    });
            return list;
        }
    }
    public IReadOnlyList<MailMessage> ListForImap(string owner, string folder)
    {
        lock (gate)
        {
            return QueryMessagesLocked(
                $"SELECT {MessageColumns} FROM messages WHERE owner_email=@o AND folder=@f ORDER BY uid",
                ("@o", owner ?? ""), ("@f", (folder ?? "").ToLowerInvariant()));
        }
    }

    public int CountUnseen(string owner, string folder) => (int)Scalar(
        "SELECT COUNT(1) FROM messages WHERE owner_email=@o AND folder=@f AND unread=1", 0L,
        ("@o", owner ?? ""), ("@f", (folder ?? "").ToLowerInvariant()));

    public int NextUidFor(string owner, string folder) { lock (gate) return NextUidLocked(owner ?? "", folder ?? ""); }

    public bool StoreFlags(string owner, string id, bool? seen, bool? flagged)
    {
        lock (gate)
        {
            var message = GetMessage(owner, id);
            if (message is null) return false;
            using var cmd = Cmd(connection, "UPDATE messages SET unread=@u, starred=@s WHERE id=@id",
                ("@u", (seen.HasValue ? !seen.Value : message.Unread) ? 1 : 0),
                ("@s", (flagged ?? message.Starred) ? 1 : 0),
                ("@id", message.Id));
            cmd.ExecuteNonQuery();
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
            return true;
        }
    }

    public bool Expunge(string owner, string id)
    {
        lock (gate)
        {
            var message = GetMessage(owner, id);
            if (message is null) return false;
            if (message.Folder.Equals("trash", StringComparison.OrdinalIgnoreCase)) DeleteRowLocked(message);
            else MoveMessage(owner, id, "trash");
            return true;
        }
    }

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

    public MailMessage? DeliverLocal(string recipient, byte[] raw, string sender)
    {
        // 投递不看激活状态：未激活的待验证账号也要能收到验证码邮件
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
            InsertMessageLocked(message);
            foreach (var recipient in recipients.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var item = new QueueItem { MessageId = message.Id, OwnerEmail = owner, Recipients = [recipient] };
                InsertQueueLocked(item);
            }
        }
        return message;
    }

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
        var raw = Mime.Build(new ComposeRequest(config.AdminEmail, "邮件系统", [owner], [], subject, text), config);

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
            InsertMessageLocked(message);
        }
        return message;
    }

    // ---------------------------------------------------------------- 出站队列

    private void InsertQueueLocked(QueueItem item)
    {
        using var cmd = Cmd(connection,
            "INSERT INTO queue(id,message_id,owner_email,recipients,attempts,created_at,next_attempt,last_attempt_at,status,last_error,last_code) " +
            "VALUES(@id,@m,@o,@r,@a,@c,@n,@l,@s,@e,@code)",
            ("@id", item.Id), ("@m", item.MessageId), ("@o", item.OwnerEmail ?? ""),
            ("@r", JsonSerializer.Serialize(item.Recipients ?? [])), ("@a", item.Attempts),
            ("@c", Ts(item.CreatedAt)), ("@n", Ts(item.NextAttempt)),
            ("@l", item.LastAttemptAt.HasValue ? Ts(item.LastAttemptAt.Value) : null),
            ("@s", item.Status), ("@e", item.LastError ?? ""), ("@code", item.LastCode));
        cmd.ExecuteNonQuery();
    }

    private static QueueItem MapQueue(SqliteDataReader r) => new()
    {
        Id = r.GetString(0),
        MessageId = r.GetString(1),
        OwnerEmail = r.GetString(2),
        Recipients = ParseStringArray(r.GetString(3)),
        Attempts = (int)r.GetInt64(4),
        CreatedAt = ParseTs(r.GetString(5), DateTimeOffset.UtcNow),
        NextAttempt = ParseTs(r.GetString(6), DateTimeOffset.UtcNow),
        LastAttemptAt = r.IsDBNull(7) ? null : ParseTs(r.GetString(7), DateTimeOffset.UtcNow),
        Status = r.GetString(8),
        LastError = r.GetString(9),
        LastCode = (int)r.GetInt64(10),
    };

    private const string QueueColumns =
        "id, message_id, owner_email, recipients, attempts, created_at, next_attempt, last_attempt_at, status, last_error, last_code";

    private static string[] ParseStringArray(string json)
    {
        try { return JsonSerializer.Deserialize<string[]>(json) ?? []; }
        catch { return []; }
    }

    private void UpdateQueueLocked(QueueItem item)
    {
        using var cmd = Cmd(connection,
            "UPDATE queue SET attempts=@a, next_attempt=@n, last_attempt_at=@l, status=@s, last_error=@e, last_code=@code WHERE id=@id",
            ("@a", item.Attempts), ("@n", Ts(item.NextAttempt)),
            ("@l", item.LastAttemptAt.HasValue ? Ts(item.LastAttemptAt.Value) : null),
            ("@s", item.Status), ("@e", item.LastError ?? ""), ("@code", item.LastCode), ("@id", item.Id));
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<QueueItem> TakeDueQueue(int limit)
    {
        lock (gate)
        {
            var due = new List<QueueItem>();
            using (var cmd = Cmd(connection,
                $"SELECT {QueueColumns} FROM queue WHERE status IN ('pending','retry') AND next_attempt <= @now " +
                "ORDER BY next_attempt LIMIT @limit",
                ("@now", Ts(DateTimeOffset.UtcNow)), ("@limit", limit)))
            using (var reader = cmd.ExecuteReader())
                while (reader.Read()) due.Add(MapQueue(reader));

            foreach (var item in due)
            {
                item.Status = "processing";
                UpdateQueueLocked(item);
            }
            if (due.Count > 0)
            {
                version++;
                WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
            }
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
            UpdateQueueLocked(item);

            var remaining = Scalar(
                "SELECT COUNT(1) FROM queue WHERE message_id=@m AND id<>@id AND status IN ('pending','retry','processing')", 0L,
                ("@m", item.MessageId), ("@id", item.Id));
            using (var cmd = Cmd(connection, "UPDATE messages SET delivery_status=@s, last_error='' WHERE id=@id",
                       ("@s", remaining > 0 ? "queued" : "sent"), ("@id", item.MessageId)))
                cmd.ExecuteNonQuery();
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
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
            var delaySeconds = Math.Min(retry.MaxDelaySeconds, retry.InitialDelaySeconds * Math.Pow(2, item.Attempts - 1));
            item.NextAttempt = DateTimeOffset.UtcNow.AddSeconds(delaySeconds);
            UpdateQueueLocked(item);

            var remaining = Scalar(
                "SELECT COUNT(1) FROM queue WHERE message_id=@m AND id<>@id AND status IN ('pending','retry','processing')", 0L,
                ("@m", item.MessageId), ("@id", item.Id));
            using (var cmd = Cmd(connection, "UPDATE messages SET delivery_status=@s, last_error=@e WHERE id=@id",
                       ("@s", gaveUp && remaining == 0 ? "failed" : "queued"), ("@e", error.Message), ("@id", item.MessageId)))
                cmd.ExecuteNonQuery();
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
        }
    }

    public void RetryQueueItem(string owner, string queueId) =>
        Mutate("UPDATE queue SET status='pending', attempts=0, next_attempt=@n, last_error='' " +
               "WHERE id=@id AND owner_email=@o",
            ("@n", Ts(DateTimeOffset.UtcNow)), ("@id", queueId ?? ""), ("@o", owner ?? ""));

    public IReadOnlyList<QueueItem> ListQueue(string owner)
    {
        lock (gate)
        {
            var list = new List<QueueItem>();
            using var cmd = Cmd(connection,
                $"SELECT {QueueColumns} FROM queue WHERE owner_email=@o ORDER BY created_at DESC", ("@o", owner ?? ""));
            using var reader = cmd.ExecuteReader();
            while (reader.Read()) list.Add(MapQueue(reader));
            return list;
        }
    }

    public object Stats(string owner)
    {
        owner ??= "";
        lock (gate)
        {
            // 返回值类型必须与 FileStore 完全一致（int），否则两套后端对客户端就不是同一个契约。
            int Count(string where, params (string, object?)[] extra)
            {
                var args = new List<(string, object?)> { ("@o", owner) };
                args.AddRange(extra);
                return (int)Scalar($"SELECT COUNT(1) FROM messages WHERE owner_email=@o AND {where}", 0L, args.ToArray());
            }

            return new
            {
                inbox = Count("folder='inbox'"),
                unread = Count("folder='inbox' AND unread=1"),
                starred = Count("starred=1 AND folder<>'trash'"),
                drafts = Count("folder='drafts'"),
                sent = Count("folder='sent'"),
                trash = Count("folder='trash'"),
                queue = (int)Scalar("SELECT COUNT(1) FROM queue WHERE owner_email=@o AND status IN ('pending','retry','processing')", 0L, ("@o", owner)),
                failed = Count("delivery_status='failed'"),
            };
        }
    }

    // ---------------------------------------------------------------- 维护

    public IReadOnlyList<MailMessage> AllMessages()
    {
        lock (gate) return QueryMessagesLocked($"SELECT {MessageColumns} FROM messages");
    }

    public IReadOnlyList<MailUser> AllUsers() => ListUsers();

    /// <summary>
    /// SQLite 实现里写入即提交。这里做一次 TRUNCATE 检查点把 WAL 归并回主库并截断，
    /// 既能让文件大小反映真实占用，也便于备份时只拷主库文件。
    /// </summary>
    public void Persist()
    {
        lock (gate)
        {
            using var cmd = Cmd(connection, "PRAGMA wal_checkpoint(TRUNCATE)");
            cmd.ExecuteNonQuery();
        }
    }

    /// <summary>回收空闲页，把数据库文件真正缩小（--vacuum）。</summary>
    public void Vacuum()
    {
        lock (gate)
        {
            using var cmd = Cmd(connection, "VACUUM");
            cmd.ExecuteNonQuery();
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); } catch { }
    }

    // ---------------------------------------------------------------- 账号体系（注册 / 验证码 / 审计）

    public void UpdateProfile(string email, string displayName) =>
        Mutate("UPDATE users SET display_name=@d WHERE email=@e",
            ("@d", displayName ?? ""), ("@e", (email ?? "").Trim()));

    public void SetLastLogin(string email) =>
        Mutate("UPDATE users SET last_login_at=@t WHERE email=@e",
            ("@t", Ts(DateTimeOffset.UtcNow)), ("@e", (email ?? "").Trim()));

    public void SaveVerificationCode(VerificationCode code)
    {
        lock (gate)
        {
            using (var cmd = Cmd(connection,
                       "INSERT INTO verification_codes(email,purpose,code_hash,salt,payload,expires_at,attempts,created_at,sent_at) " +
                       "VALUES(@e,@p,@h,@s,@y,@x,@a,@c,@t) " +
                       "ON CONFLICT(email,purpose) DO UPDATE SET code_hash=@h, salt=@s, payload=@y, " +
                       "expires_at=@x, attempts=0, created_at=@c, sent_at=@t",
                       ("@e", code.Email), ("@p", code.Purpose), ("@h", code.CodeHash), ("@s", code.Salt),
                       ("@y", code.Payload ?? ""), ("@x", Ts(code.ExpiresAt)), ("@a", code.Attempts),
                       ("@c", Ts(code.CreatedAt)), ("@t", code.SentAt is null ? null : Ts(code.SentAt.Value))))
                cmd.ExecuteNonQuery();
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
        }
    }

    public VerificationCode? FindVerificationCode(string email, string purpose)
    {
        lock (gate)
        {
            using var cmd = Cmd(connection,
                "SELECT email,purpose,code_hash,salt,payload,expires_at,attempts,created_at,sent_at " +
                "FROM verification_codes WHERE email=@e AND purpose=@p",
                ("@e", (email ?? "").Trim()), ("@p", purpose));
            using var reader = cmd.ExecuteReader();
            if (!reader.Read()) return null;
            return new VerificationCode
            {
                Email = reader.GetString(0),
                Purpose = reader.GetString(1),
                CodeHash = reader.GetString(2),
                Salt = reader.GetString(3),
                Payload = reader.GetString(4),
                ExpiresAt = ParseTs(reader.GetString(5), DateTimeOffset.UtcNow),
                Attempts = reader.GetInt32(6),
                CreatedAt = ParseTs(reader.GetString(7), DateTimeOffset.UtcNow),
                SentAt = reader.IsDBNull(8) ? null : ParseTs(reader.GetString(8), DateTimeOffset.UtcNow),
            };
        }
    }

    public int IncrementVerificationAttempts(string email, string purpose)
    {
        Mutate("UPDATE verification_codes SET attempts=attempts+1 WHERE email=@e AND purpose=@p",
            ("@e", (email ?? "").Trim()), ("@p", purpose));
        return (int)Scalar("SELECT attempts FROM verification_codes WHERE email=@e AND purpose=@p", 0L,
            ("@e", (email ?? "").Trim()), ("@p", purpose));
    }

    public void RemoveVerificationCode(string email, string purpose) =>
        Mutate("DELETE FROM verification_codes WHERE email=@e AND purpose=@p",
            ("@e", (email ?? "").Trim()), ("@p", purpose));

    public void RecordAuthEvent(AuthEvent entry)
    {
        lock (gate)
        {
            using (var cmd = Cmd(connection,
                       "INSERT INTO auth_events(id,email,ip,reason,success,detail,user_agent,at) " +
                       "VALUES(@i,@e,@p,@r,@o,@d,@u,@t)",
                       ("@i", entry.Id), ("@e", entry.Email ?? ""), ("@p", entry.Ip ?? ""), ("@r", entry.Reason ?? ""),
                       ("@o", entry.Success ? 1 : 0), ("@d", entry.Detail ?? ""), ("@u", entry.UserAgent ?? ""),
                       ("@t", Ts(entry.At))))
                cmd.ExecuteNonQuery();
            // 顺手淘汰超量审计（每 50 条才做一次，避免每次都付代价）
            auditWrites++;
            if (auditWrites % 50 == 0) PruneAuthEventsLocked(AuditKeep);
            version++;
            WriteMetaLocked("version", version.ToString(CultureInfo.InvariantCulture));
        }
    }

    private int auditWrites;

    /// <summary>审计保留条数（由配置注入；默认 2000）。</summary>
    public int AuditKeep { get; set; } = 2000;

    private void PruneAuthEventsLocked(int keep)
    {
        using var cmd = Cmd(connection,
            "DELETE FROM auth_events WHERE id NOT IN (SELECT id FROM auth_events ORDER BY at DESC LIMIT @k)",
            ("@k", Math.Max(100, keep)));
        cmd.ExecuteNonQuery();
    }

    public IReadOnlyList<AuthEvent> ListAuthEvents(string? email, string? ip, string? reason, int limit)
    {
        var sql = "SELECT id,email,ip,reason,success,detail,user_agent,at FROM auth_events WHERE 1=1";
        var args = new List<(string, object?)>();
        if (!string.IsNullOrWhiteSpace(email)) { sql += " AND email=@e"; args.Add(("@e", email.Trim())); }
        if (!string.IsNullOrWhiteSpace(ip)) { sql += " AND ip=@p"; args.Add(("@p", ip.Trim())); }
        if (!string.IsNullOrWhiteSpace(reason)) { sql += " AND reason=@r"; args.Add(("@r", reason.Trim())); }
        sql += " ORDER BY at DESC LIMIT @k";
        args.Add(("@k", Math.Clamp(limit <= 0 ? 200 : limit, 1, 5000)));

        lock (gate)
        {
            var list = new List<AuthEvent>();
            using var cmd = Cmd(connection, sql, [.. args]);
            using var reader = cmd.ExecuteReader();
            while (reader.Read())
            {
                list.Add(new AuthEvent
                {
                    Id = reader.GetString(0),
                    Email = reader.GetString(1),
                    Ip = reader.GetString(2),
                    Reason = reader.GetString(3),
                    Success = reader.GetInt32(4) != 0,
                    Detail = reader.GetString(5),
                    UserAgent = reader.GetString(6),
                    At = ParseTs(reader.GetString(7), DateTimeOffset.UtcNow),
                });
            }
            return list;
        }
    }

    public int CountAuthEvents(string? email, string? ip, string? reason, bool? success, int minutes)
    {
        var since = Ts(DateTimeOffset.UtcNow.AddMinutes(-Math.Max(1, minutes)));
        var sql = "SELECT COUNT(1) FROM auth_events WHERE at >= @since";
        var args = new List<(string, object?)> { ("@since", since) };
        if (!string.IsNullOrWhiteSpace(email)) { sql += " AND email=@e"; args.Add(("@e", email.Trim())); }
        if (!string.IsNullOrWhiteSpace(ip)) { sql += " AND ip=@p"; args.Add(("@p", ip.Trim())); }
        if (!string.IsNullOrWhiteSpace(reason)) { sql += " AND reason=@r"; args.Add(("@r", reason.Trim())); }
        if (success.HasValue) { sql += " AND success=@o"; args.Add(("@o", success.Value ? 1 : 0)); }
        return (int)Scalar(sql, 0L, [.. args]);
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

    public void Dispose()
    {
        try { connection.Dispose(); } catch { }
    }
}
