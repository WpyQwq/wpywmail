namespace WpywMail.Native;

/// <summary>
/// 邮件存储的统一接口。
///
/// 之所以要抽出接口：v2.0.x 只有 <see cref="FileStore"/> 一种实现，任何一次改动
/// （哪怕只是把一封邮件标记为已读）都要把**全部邮件**重新序列化并整文件重写，
/// 且 UID 分配、搜索、统计全是 O(N) 全表扫描。引入 <see cref="SqliteStore"/> 后
/// 上层（API / IMAP / SMTP / 投递队列）不需要知道底下是 JSON 还是 SQLite。
/// </summary>
public interface IMailStore : IDisposable
{
    /// <summary>每次写入自增，供长轮询判断「有没有新变化」。</summary>
    long Version { get; }

    // ---------------------------------------------------------------- 用户
    MailUser? FindUser(string email);
    /// <summary>
    /// 不看过滤 active 的查号。用途：① 投递（信箱先存在、访问才受控）；
    /// ② 登录时区分「密码错」与「账号未激活/已停用」（真实原因只进审计）。
    /// </summary>
    MailUser? FindUserAnyState(string email);
    MailUser? Authenticate(string email, string password);
    bool IsLocalAddress(string email);
    IReadOnlyList<MailUser> ListUsers();
    MailUser CreateUser(string email, string password, string displayName);
    /// <summary>用已经算好的哈希建号（注册验证通过时用，避免明文密码再走一遍内存）。</summary>
    MailUser CreateUserWithHash(string email, string passwordHash, string passwordSalt, string displayName, bool active = true);
    void ChangePassword(string email, string password);
    void SetUserActive(string email, bool active);
    /// <summary>
    /// 彻底删除一个账号：用户行 + 它的会话 + 验证码 + 它名下的出站队列。
    /// **邮件不在这里删** —— 调用方要先 ListMessages + DeleteMessage(permanent:true) 逐封删，
    /// 那样才会顺带回收无引用的大对象。审计保留（删除动作本身也会写一条审计）。
    /// </summary>
    bool DeleteUser(string email);

    // ---------------------------------------------------------------- 会话
    SessionRecord CreateSession(string email, int days);
    SessionRecord? GetSession(string? token);
    void RemoveSession(string token);
    /// <summary>列出某个账号的全部活跃会话（用于「在哪登录了 / 退出其他设备」）。</summary>
    IReadOnlyList<SessionRecord> ListSessions(string email);
    /// <summary>吊销该账号的会话；keepToken 非空时保留它（即「退出其他设备」）。返回吊销数量。</summary>
    int RemoveSessions(string email, string? keepToken);

    // ---------------------------------------------------------------- 账号体系（注册 / 验证码 / 审计）
    /// <summary>把用户资料写回存储（目前只有显示名）。</summary>
    void UpdateProfile(string email, string displayName);
    /// <summary>记录一次成功登录时间。</summary>
    void SetLastLogin(string email);

    /// <summary>保存验证码（同一 email+purpose 覆盖旧的）。只存哈希。</summary>
    void SaveVerificationCode(VerificationCode code);
    VerificationCode? FindVerificationCode(string email, string purpose);
    /// <summary>验证码试错次数 +1，返回自增后的次数。</summary>
    int IncrementVerificationAttempts(string email, string purpose);
    void RemoveVerificationCode(string email, string purpose);

    /// <summary>写一条认证审计。</summary>
    void RecordAuthEvent(AuthEvent entry);
    /// <summary>按条件查审计（都为 null 表示不限制）；limit 为 0 时用实现自己的默认上限。</summary>
    IReadOnlyList<AuthEvent> ListAuthEvents(string? email, string? ip, string? reason, int limit);
    /// <summary>统计窗口期内的认证事件数量（登录锁定、注册与重发限流都用它）。</summary>
    int CountAuthEvents(string? email, string? ip, string? reason, bool? success, int minutes);

    // ---------------------------------------------------------------- 原始报文与附件
    string SaveRaw(byte[] raw);
    byte[] ReadRaw(string relativePath);
    string SaveAttachment(byte[] data, string suggestedName);
    byte[] ReadAttachment(string relativePath);

    // ---------------------------------------------------------------- 邮件
    MailMessage SaveMessage(MailMessage message, byte[]? raw = null);
    MailMessage? DeliverLocal(string recipient, byte[] raw, string sender);
    MailMessage QueueOutbound(string owner, string[] recipients, string subject, string text,
        byte[] raw, string cc = "", string html = "", string inReplyTo = "",
        IReadOnlyList<Attachment>? attachments = null);
    MailMessage CreateBounce(string owner, string originalSubject, string[] recipients, string error, string originalRawPath);
    IReadOnlyList<MailMessage> ListMessages(string owner, string folder, string query);
    /// <summary>分页查询：只取需要的一页（SQLite 直接下推到 SQL，不再把整个邮箱读进内存）。</summary>
    (int Total, IReadOnlyList<MailMessage> Messages) ListMessagesPage(
        string owner, string folder, string query, bool unreadOnly, bool starredOnly, int limit, int offset);
    MailMessage? GetMessage(string owner, string id);
    MailMessage? GetById(string id);
    bool MarkRead(string owner, string id, bool read);
    bool SetStar(string owner, string id, bool starred);
    bool MoveMessage(string owner, string id, string folder);
    bool DeleteMessage(string owner, string id, bool permanent);
    object Stats(string owner);

    // ---------------------------------------------------------------- IMAP
    IReadOnlyList<MailMessage> ListForImap(string owner, string folder);
    MailMessage? GetByUid(string owner, string folder, int uid);
    bool StoreFlags(string owner, string id, bool? seen, bool? flagged);
    bool Expunge(string owner, string id);
    MailMessage? Append(string owner, string folder, byte[] raw, bool seen);
    int CountUnseen(string owner, string folder);
    int NextUidFor(string owner, string folder);

    // ---------------------------------------------------------------- 出站队列
    IReadOnlyList<QueueItem> TakeDueQueue(int limit);
    void CompleteQueue(QueueItem item);
    void FailQueue(QueueItem item, Exception error, RetryConfig retry, out bool gaveUp);
    void RetryQueueItem(string owner, string queueId);
    IReadOnlyList<QueueItem> ListQueue(string owner);

    // ---------------------------------------------------------------- 维护
    IReadOnlyList<MailMessage> AllMessages();
    IReadOnlyList<MailUser> AllUsers();
    /// <summary>把内存中的改动落盘。JSON 实现会整文件重写；SQLite 实现是空操作（写入即提交）。</summary>
    void Persist();
}

/// <summary>存储占用统计。</summary>
public sealed class StoreUsage
{
    public string Provider { get; set; } = "";
    public string Database { get; set; } = "";
    public long DbBytes { get; set; }
    public long WalBytes { get; set; }
    public long Blobs { get; set; }
    public long BlobRawBytes { get; set; }
    public long BlobStoredBytes { get; set; }
    public long BlobGzipped { get; set; }
    public long Messages { get; set; }
    public long Orphans { get; set; }
    /// <summary>正文文本占用的字节数（text_body + html_body），用于判断「重复存储」的成本。</summary>
    public long TextBytes { get; set; }
    /// <summary>数据库空闲页字节数（未 VACUUM 时会被计入文件大小）。</summary>
    public long FreeBytes { get; set; }
    /// <summary>数据库实际使用的页字节数（page_count × page_size）。</summary>
    public long TotalBytes { get; set; }
    /// <summary>文件高水位（含已回收但未归还操作系统的空间）。</summary>
    public long PageCount { get; set; }
    public long PageSize { get; set; }
    /// <summary>最大一封邮件的正文长度与其主题（排查「空间被谁吃了」）。</summary>
    public long LargestTextBytes { get; set; }
    public string LargestTextSubject { get; set; } = "";
}

/// <summary>文件夹常量与名称归一化（IMAP 与 API 共用）。</summary>
public static class MailFolders
{
    /// <summary>IMAP 用的文件夹列表（固定集合，未使用也返回，便于客户端订阅）。</summary>
    public static readonly string[] ImapFolders = ["inbox", "sent", "drafts", "archive", "trash", "spam"];

    /// <summary>把客户端给的各种写法（含中文别名）归一化成内部文件夹名；无法识别返回 null。</summary>
    public static string? Normalize(string name)
    {
        var key = (name ?? "").Trim().Trim('"').ToLowerInvariant();
        if (key is "inbox" or "收件箱") return "inbox";
        if (key is "sent" or "sent items" or "sent messages" or "已发送") return "sent";
        if (key is "drafts" or "草稿") return "drafts";
        if (key is "archive" or "archives" or "归档") return "archive";
        if (key is "trash" or "deleted" or "deleted items" or "已删除" or "垃圾箱") return "trash";
        if (key is "junk" or "spam" or "垃圾邮件") return "spam";
        return null;
    }
}
