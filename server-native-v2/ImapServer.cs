using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace WpywMail.Native;

/// <summary>
/// IMAP4rev1 服务端（RFC 3501 子集）。
///
/// 目的：让标准邮件客户端（Outlook / Thunderbird / Foxmail / 手机邮件 App）
/// 直接接入，而不必依赖自研客户端；自研客户端仍可继续用 REST。
///
/// 支持：CAPABILITY、NOOP、LOGOUT、STARTTLS、LOGIN、AUTHENTICATE PLAIN、
///       LIST/LSUB、SELECT/EXAMINE、STATUS、CREATE/DELETE/RENAME（受限）、CLOSE、
///       EXPUNGE、SEARCH、FETCH/UID FETCH、STORE/UID STORE、COPY/UID COPY、APPEND、IDLE。
/// 未实现（客户端可正常工作）：CONDSTORE、QRESYNC、SORT、THREAD、UIDPLUS、ACL。
/// </summary>
public sealed class ImapServer
{
    private const string Crlf = "\r\n";
    private readonly AppConfig config;
    private readonly IMailStore store;
    private readonly X509Certificate2? certificate;

    public ImapServer(AppConfig config, IMailStore store)
    {
        this.config = config;
        this.store = store;
        if (!string.IsNullOrWhiteSpace(config.TlsCertificatePath) && File.Exists(config.TlsCertificatePath))
            certificate = new X509Certificate2(config.TlsCertificatePath, config.TlsCertificatePassword);
    }

    public async Task RunAsync(CancellationToken token)
    {
        if (!config.Imap.Enabled)
        {
            AppLog.Info("[IMAP] 已按配置禁用。");
            return;
        }

        var tasks = new List<Task>();
        if (config.Imap.Port > 0)
        {
            var plain = new TcpListener(IPAddress.Any, config.Imap.Port);
            plain.Start();
            AppLog.Info($"[IMAP] 已监听：{config.Imap.Port}（明文 + STARTTLS）");
            tasks.Add(AcceptLoopAsync(plain, implicitTls: false, token));
        }
        if (config.Imap.TlsPort > 0 && certificate is not null)
        {
            var tls = new TcpListener(IPAddress.Any, config.Imap.TlsPort);
            tls.Start();
            AppLog.Info($"[IMAP] 已监听：{config.Imap.TlsPort}（隐式 TLS）");
            tasks.Add(AcceptLoopAsync(tls, implicitTls: true, token));
        }
        else if (config.Imap.TlsPort > 0)
        {
            AppLog.Warn($"[IMAP] {config.Imap.TlsPort} 端口未启动：没有可用证书。");
        }

        await Task.WhenAll(tasks);
    }

    private async Task AcceptLoopAsync(TcpListener listener, bool implicitTls, CancellationToken token)
    {
        try
        {
            while (!token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(token);
                _ = Task.Run(async () =>
                {
                    try { await new ImapSession(config, store, certificate, implicitTls, client).RunAsync(token); }
                    catch (Exception ex) { AppLog.Error($"[IMAP] 会话异常：{ex.Message}"); }
                    finally { client.Dispose(); }
                }, token);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) { AppLog.Error($"[IMAP] 接收循环异常：{ex.Message}"); }
        finally { listener.Stop(); }
    }
}

/// <summary>单个 IMAP 连接的状态机。</summary>
internal sealed class ImapSession
{
    private const string Crlf = "\r\n";
    private readonly AppConfig config;
    private readonly IMailStore store;
    private readonly X509Certificate2? certificate;
    private readonly TcpClient client;
    private SmtpReader reader = null!;
    private Stream stream = null!;

    private string? user;
    private string? selected;                 // 当前选中的文件夹（我们的内部名）
    private bool readOnly;
    private bool authenticated;
    private bool tls;
    private readonly HashSet<string> deleted = [];   // 会话内 \Deleted 标记（按 message id）

    public ImapSession(AppConfig config, IMailStore store, X509Certificate2? certificate, bool implicitTls, TcpClient client)
    {
        this.config = config;
        this.store = store;
        this.certificate = certificate;
        this.client = client;
        _ = implicitTls;
    }

    public async Task RunAsync(CancellationToken token)
    {
        stream = client.GetStream();
        var implicitTls = client.Client.LocalEndPoint is IPEndPoint { Port: var port } && port == config.Imap.TlsPort && config.Imap.TlsPort > 0;

        if (implicitTls && certificate is not null)
        {
            var ssl = new SslStream(stream, false);
            await ssl.AuthenticateAsServerAsync(BuildTlsOptions(), token);
            stream = ssl;
            tls = true;
        }

        reader = new SmtpReader(stream);
        var writer = new StreamWriter(stream, Encoding.ASCII, 8192, true) { AutoFlush = true, NewLine = Crlf };

        var remoteIp = (client.Client.RemoteEndPoint as IPEndPoint)?.Address.ToString() ?? "";
        await WriteAsync(writer, $"* OK [CAPABILITY {Capabilities()}] WpywMail IMAP4rev1 ready");
        AppLog.Info($"[IMAP] 收到连接：{client.Client.RemoteEndPoint}，TLS={(tls ? "是" : "否")}");

        while (!token.IsCancellationRequested)
        {
            var line = await reader.ReadLineAsync(token);
            if (line is null) break;
            if (line.Length == 0) continue;

            var space = line.IndexOf(' ');
            var tag = space < 0 ? line : line[..space];
            var rest = space < 0 ? "" : line[(space + 1)..].Trim();
            var command = rest.Length == 0 ? "" : rest.Split(' ')[0].ToUpperInvariant();
            // 各处理器只接受「参数」，因此这里必须把命令名本身剥掉
            var args = rest.Length > command.Length ? rest[command.Length..].Trim() : "";

            try
            {
                if (command == "LOGOUT")
                {
                    await WriteAsync(writer, "* BYE WpywMail IMAP4rev1 signing off");
                    await WriteAsync(writer, $"{tag} OK LOGOUT completed");
                    break;
                }

                if (command == "CAPABILITY") { await WriteAsync(writer, $"* CAPABILITY {Capabilities()}"); await OkAsync(writer, tag, "CAPABILITY completed"); continue; }
                if (command == "NOOP") { await OkAsync(writer, tag, "NOOP completed"); continue; }
                if (command == "STARTTLS")
                {
                    if (tls || certificate is null) { await NoAsync(writer, tag, "STARTTLS not available"); continue; }
                    await OkAsync(writer, tag, "Begin TLS negotiation now");   // RFC 3501: STARTTLS 的响应是带 tag 的 OK
                    var ssl = new SslStream(stream, false);
                    await ssl.AuthenticateAsServerAsync(BuildTlsOptions(), token);
                    stream = ssl;
                    reader = new SmtpReader(stream);
                    try { writer.Dispose(); } catch { }
                    writer = new StreamWriter(stream, Encoding.ASCII, 8192, true) { AutoFlush = true, NewLine = Crlf };
                    tls = true;
                    AppLog.Info($"[IMAP] {remoteIp} 已建立 TLS 会话。");
                    continue;
                }

                if (!authenticated)
                {
                    if (command == "LOGIN")
                    {
                        var (u, p) = ParseLogin(rest);
                        if (!TlsSatisfied(remoteIp)) { await NoAsync(writer, tag, "LOGIN requires TLS (issue STARTTLS first)"); continue; }
                        var account = store.Authenticate(u, p);
                        if (account is null) { AppLog.Warn($"[IMAP] {remoteIp} 登录失败：{u}"); await NoAsync(writer, tag, "LOGIN failed"); continue; }
                        user = account.Email;
                        authenticated = true;
                        AppLog.Info($"[IMAP] {remoteIp} 登录成功：{user}");
                        await OkAsync(writer, tag, "LOGIN completed");
                        continue;
                    }
                    if (command == "AUTHENTICATE")
                    {
                        if (!TlsSatisfied(remoteIp)) { await NoAsync(writer, tag, "AUTHENTICATE requires TLS"); continue; }
                        var mechanism = rest.Split(' ', 2).ElementAtOrDefault(1)?.ToUpperInvariant() ?? "";
                        if (mechanism != "PLAIN") { await NoAsync(writer, tag, "Unsupported authentication mechanism"); continue; }
                        var payload = rest.Split(' ', 3).ElementAtOrDefault(2);
                        if (string.IsNullOrEmpty(payload))
                        {
                            await WriteAsync(writer, "+ ");
                            payload = (await reader.ReadLineAsync(token) ?? "").Trim();
                        }
                        var ok = TryParsePlain(payload, out var u, out var p);
                        var account = ok ? store.Authenticate(u, p) : null;
                        if (account is null) { await NoAsync(writer, tag, "AUTHENTICATE failed"); continue; }
                        user = account.Email;
                        authenticated = true;
                        await OkAsync(writer, tag, "AUTHENTICATE completed");
                        continue;
                    }
                    await NoAsync(writer, tag, "Please authenticate first");
                    continue;
                }

                switch (command)
                {
                    case "LIST":
                    case "LSUB":
                        await WriteAsync(writer, $"* {(command == "LSUB" ? "LSUB" : "LIST")} (\\HasNoChildren) \"/\" \"INBOX\"");
                        foreach (var folder in MailFolders.ImapFolders.Where(f => f != "inbox"))
                            await WriteAsync(writer, $"* {command} (\\HasNoChildren) \"/\" \"{DisplayName(folder)}\"");
                        await OkAsync(writer, tag, $"{command} completed");
                        break;

                    case "SELECT":
                    case "EXAMINE":
                        await SelectAsync(writer, tag, args, readOnlyRequested: command == "EXAMINE");
                        break;

                    case "STATUS":
                        await StatusAsync(writer, tag, args);
                        break;

                    case "CLOSE":
                        selected = null;
                        deleted.Clear();
                        await OkAsync(writer, tag, "CLOSE completed");
                        break;

                    case "UNSELECT":
                        selected = null;
                        await OkAsync(writer, tag, "UNSELECT completed");
                        break;

                    case "CREATE":
                    case "DELETE":
                    case "RENAME":
                    case "SUBSCRIBE":
                    case "UNSUBSCRIBE":
                        // 文件夹集合固定，接受但不做实际变更
                        await OkAsync(writer, tag, $"{command} completed");
                        break;

                    case "EXPUNGE":
                        await ExpungeAsync(writer, tag);
                        break;

                    case "SEARCH":
                        await SearchAsync(writer, tag, args, useUid: false);
                        break;

                    case "UID":
                        await SearchOrUidAsync(writer, tag, args, token);
                        break;

                    case "FETCH":
                        await FetchAsync(writer, tag, args, useUid: false);
                        break;

                    case "STORE":
                        await StoreAsync(writer, tag, args, useUid: false);
                        break;

                    case "COPY":
                        await CopyAsync(writer, tag, args, useUid: false);
                        break;

                    case "APPEND":
                        await AppendAsync(writer, tag, args, token);
                        break;

                    case "CHECK":
                        await OkAsync(writer, tag, "CHECK completed");
                        break;

                    case "IDLE":
                        await IdleAsync(writer, tag, token);
                        break;

                    default:
                        await NoAsync(writer, tag, $"Command not supported: {command}");
                        break;
                }
            }
            catch (Exception ex)
            {
                AppLog.Error($"[IMAP] 处理 {command} 出错：{ex.Message}");
                await NoAsync(writer, tag, "Internal error");
            }
        }

        try { writer.Dispose(); } catch { }
        AppLog.Info($"[IMAP] 连接结束：{remoteIp}");
    }

    private SslServerAuthenticationOptions BuildTlsOptions() => new()
    {
        ServerCertificate = certificate,
        EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
        ClientCertificateRequired = false,
    };

    private string Capabilities() =>
        "IMAP4rev1 " + (certificate is not null && !tls ? "STARTTLS " : "") + "AUTH=PLAIN IDLE UIDPLUS CHILDREN NAMESPACE";

    private bool TlsSatisfied(string remoteIp)
    {
        if (tls || !config.Imap.RequireTlsForLogin) return true;
        return config.Imap.PlaintextLoginAllowFrom.Contains(remoteIp);
    }

    // ---------------------------------------------------------------- SELECT / STATUS

    private async Task SelectAsync(StreamWriter writer, string tag, string rest, bool readOnlyRequested)
    {
        var mailbox = ExtractMailbox(rest);
        var folder = MailFolders.Normalize(mailbox);
        if (folder is null) { await NoAsync(writer, tag, "Mailbox does not exist"); return; }

        selected = folder;
        readOnly = readOnlyRequested;
        deleted.Clear();

        var items = store.ListForImap(user!, folder);
        var unseen = items.Count(x => x.Unread);
        var nextUid = store.NextUidFor(user!, folder);

        await WriteAsync(writer, $"* {items.Count} EXISTS");
        await WriteAsync(writer, $"* {unseen} RECENT");
        await WriteAsync(writer, "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)");
        await WriteAsync(writer, $"* OK [PERMANENTFLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft \\*)] Limited");
        await WriteAsync(writer, "* OK [UIDVALIDITY 1] UIDs valid");
        await WriteAsync(writer, $"* OK [UIDNEXT {nextUid}] Predicted next UID");
        await OkAsync(writer, tag, $"[READ-{(readOnly ? "ONLY" : "WRITE")}] {(readOnlyRequested ? "EXAMINE" : "SELECT")} completed");
    }

    private async Task StatusAsync(StreamWriter writer, string tag, string rest)
    {
        var parts = SplitTokens(rest);
        if (parts.Count < 2) { await NoAsync(writer, tag, "STATUS requires mailbox and items"); return; }
        var folder = MailFolders.Normalize(parts[0]);
        if (folder is null) { await NoAsync(writer, tag, "Mailbox does not exist"); return; }

        var items = store.ListForImap(user!, folder);
        var requested = parts[1].Trim('(', ')').ToUpperInvariant();
        var values = new List<string>();
        if (requested.Contains("MESSAGES")) values.Add($"MESSAGES {items.Count}");
        if (requested.Contains("RECENT")) values.Add($"RECENT {items.Count(x => x.Unread)}");
        if (requested.Contains("UNSEEN")) values.Add($"UNSEEN {items.Count(x => x.Unread)}");
        if (requested.Contains("UIDNEXT")) values.Add($"UIDNEXT {store.NextUidFor(user!, folder)}");
        if (requested.Contains("UIDVALIDITY")) values.Add("UIDVALIDITY 1");
        await WriteAsync(writer, $"* STATUS \"{DisplayName(folder)}\" ({string.Join(" ", values)})");
        await OkAsync(writer, tag, "STATUS completed");
    }

    // ---------------------------------------------------------------- SEARCH / FETCH

    private async Task SearchOrUidAsync(StreamWriter writer, string tag, string rest, CancellationToken token)
    {
        var space = rest.IndexOf(' ');
        var sub = space < 0 ? rest.ToUpperInvariant() : rest[..space].ToUpperInvariant();
        var args = space < 0 ? "" : rest[(space + 1)..];

        switch (sub)
        {
            case "SEARCH": await SearchAsync(writer, tag, args, useUid: false); break;
            case "FETCH": await FetchAsync(writer, tag, args, useUid: true); break;
            case "STORE": await StoreAsync(writer, tag, args, useUid: true); break;
            case "COPY": await CopyAsync(writer, tag, args, useUid: true); break;
            default: await NoAsync(writer, tag, $"UID {sub} not supported"); break;
        }
        await Task.CompletedTask;
        _ = token;
    }

    private async Task SearchAsync(StreamWriter writer, string tag, string args, bool useUid)
    {
        if (selected is null) { await NoAsync(writer, tag, "No mailbox selected"); return; }
        var items = store.ListForImap(user!, selected);
        var criteria = args.ToUpperInvariant();
        if (criteria.StartsWith("CHARSET")) criteria = criteria[(criteria.IndexOf(' ') + 1)..];

        IEnumerable<MailMessage> result = items;
        if (criteria.Contains("UNSEEN")) result = result.Where(x => x.Unread);
        if (criteria.Contains("SEEN")) result = result.Where(x => !x.Unread);
        if (criteria.Contains("FLAGGED")) result = result.Where(x => x.Starred);
        if (criteria.Contains("UNFLAGGED")) result = result.Where(x => !x.Starred);
        if (criteria.Contains("DELETED")) result = result.Where(x => deleted.Contains(x.Id));

        var fromIndex = criteria.IndexOf("FROM ", StringComparison.Ordinal);
        if (fromIndex >= 0)
        {
            var needle = Unquote(criteria[(fromIndex + 5)..].Split(' ')[0]);
            result = result.Where(x => x.From.Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
        var subjectIndex = criteria.IndexOf("SUBJECT ", StringComparison.Ordinal);
        if (subjectIndex >= 0)
        {
            var needle = Unquote(criteria[(subjectIndex + 8)..].Split(' ')[0]);
            result = result.Where(x => x.Subject.Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
        var textIndex = criteria.IndexOf("TEXT ", StringComparison.Ordinal);
        if (textIndex >= 0)
        {
            var needle = Unquote(criteria[(textIndex + 5)..].Split(' ')[0]);
            result = result.Where(x => (x.Subject + " " + x.Text).Contains(needle, StringComparison.OrdinalIgnoreCase));
        }
        var uidIndex = criteria.IndexOf("UID ", StringComparison.Ordinal);
        if (uidIndex >= 0)
        {
            var set = criteria[(uidIndex + 4)..].Split(' ')[0];
            var uids = ParseUidSet(set, items);
            result = result.Where(x => uids.Contains(x.Uid));
        }

        var ids = result.Select(x => useUid ? x.Uid : IndexOf(items, x) + 1);
        await WriteAsync(writer, "* SEARCH " + string.Join(" ", ids));
        await OkAsync(writer, tag, "SEARCH completed");
    }

    private async Task FetchAsync(StreamWriter writer, string tag, string args, bool useUid)
    {
        if (selected is null) { await NoAsync(writer, tag, "No mailbox selected"); return; }
        var parts = SplitTokens(args);
        if (parts.Count < 2) { await NoAsync(writer, tag, "FETCH requires set and items"); return; }

        var items = store.ListForImap(user!, selected);
        var targets = ResolveSet(parts[0], items, useUid);
        var spec = args[(args.IndexOf(' ') + 1)..];   // 保留原始大小写，便于解析 BODY[...]
        var wantsUid = spec.Contains("UID", StringComparison.OrdinalIgnoreCase) || useUid;

        foreach (var message in targets)
        {
            var pieces = new List<string>();
            if (wantsUid) pieces.Add($"UID {message.Uid}");
            if (HasToken(spec, "FLAGS")) pieces.Add("FLAGS " + FlagsOf(message));
            if (HasToken(spec, "INTERNALDATE")) pieces.Add("INTERNALDATE \"" + FormatInternalDate(message.Date) + "\"");
            if (HasToken(spec, "ENVELOPE")) pieces.Add("ENVELOPE " + Envelope(message));

            var wantsStructure = SpecNeedsBodyStructure(spec);
            var bodyItem = ExtractBodyItem(spec);

            if (wantsStructure) pieces.Add("BODYSTRUCTURE " + BodyStructure(message));

            // 取正文时顺带拿到原始字节，既能回退计算大小，也避免重复读盘
            byte[]? rawForSize = null;
            long ActualSize()
            {
                if (message.Size > 0) return message.Size;
                rawForSize ??= SafeReadRaw(message);
                return rawForSize.Length;
            }

            if (HasToken(spec, "RFC822.SIZE")) pieces.Add($"RFC822.SIZE {ActualSize()}");

            // 精确匹配 RFC822 / RFC822.HEADER / RFC822.TEXT，避免 "RFC822.SIZE" 被误判成整封请求
            var wantsRfc822 = HasToken(spec, "RFC822");
            var wantsRfc822Header = HasToken(spec, "RFC822.HEADER");
            var wantsRfc822Text = HasToken(spec, "RFC822.TEXT");

            if (bodyItem is not null || wantsRfc822 || wantsRfc822Header || wantsRfc822Text)
            {
                var (section, peek, label, fields) = bodyItem
                    ?? (wantsRfc822Header ? "HEADER" : wantsRfc822Text ? "TEXT" : "", false,
                        wantsRfc822Header ? "RFC822.HEADER" : wantsRfc822Text ? "RFC822.TEXT" : "RFC822", Array.Empty<string>());
                var content = RenderSection(message, section, fields);
                var responseLabel = label.StartsWith("RFC822") ? label : label;

                // 除了 PEEK 之外，取正文视为已读
                if (!peek && message.Unread)
                {
                    store.MarkRead(user!, message.Id, true);
                    message.Unread = false;
                }

                await WriteAsync(writer, $"* {(useUid ? message.Uid : IndexOf(items, message) + 1)} FETCH ({string.Join(" ", pieces)} {responseLabel} {{{content.Length}}}");
                await WriteBytesAsync(writer, content);
                await WriteAsync(writer, ")");
                continue;
            }

            await WriteAsync(writer, $"* {(useUid ? message.Uid : IndexOf(items, message) + 1)} FETCH ({string.Join(" ", pieces)})");
        }

        await OkAsync(writer, tag, "FETCH completed");
    }

    private async Task StoreAsync(StreamWriter writer, string tag, string args, bool useUid)
    {
        if (selected is null) { await NoAsync(writer, tag, "No mailbox selected"); return; }
        if (readOnly) { await NoAsync(writer, tag, "Mailbox is read-only"); return; }

        var parts = SplitTokens(args);
        if (parts.Count < 3) { await NoAsync(writer, tag, "STORE requires set, item and flags"); return; }

        var items = store.ListForImap(user!, selected);
        var targets = ResolveSet(parts[0], items, useUid);
        var operation = parts[1].ToUpperInvariant();
        var silent = operation.EndsWith(".SILENT");
        var flags = args[(args.IndexOf(parts[2], StringComparison.Ordinal))..].ToUpperInvariant();
        var add = !operation.StartsWith("-FLAGS");
        var remove = operation.StartsWith("-FLAGS");

        foreach (var message in targets)
        {
            if (flags.Contains("\\SEEN")) store.StoreFlags(user!, message.Id, seen: add && !remove, flagged: null);
            if (flags.Contains("\\FLAGGED")) store.StoreFlags(user!, message.Id, seen: null, flagged: add && !remove);
            if (flags.Contains("\\DELETED"))
            {
                if (add && !remove) deleted.Add(message.Id);
                else deleted.Remove(message.Id);
            }

            var updated = store.GetMessage(user!, message.Id)!;
            if (!silent)
                await WriteAsync(writer, $"* {(useUid ? updated.Uid : IndexOf(items, updated) + 1)} FETCH (FLAGS {FlagsOf(updated)})");
        }

        await OkAsync(writer, tag, "STORE completed");
    }

    private async Task CopyAsync(StreamWriter writer, string tag, string args, bool useUid)
    {
        if (selected is null) { await NoAsync(writer, tag, "No mailbox selected"); return; }
        var parts = SplitTokens(args);
        if (parts.Count < 2) { await NoAsync(writer, tag, "COPY requires set and mailbox"); return; }
        var folder = MailFolders.Normalize(parts[1]);
        if (folder is null) { await NoAsync(writer, tag, "TRYCREATE Mailbox does not exist"); return; }

        var items = store.ListForImap(user!, selected);
        foreach (var message in ResolveSet(parts[0], items, useUid))
        {
            try
            {
                var raw = store.ReadRaw(message.RawPath);
                store.Append(user!, folder, raw, seen: true);
            }
            catch (Exception ex)
            {
                AppLog.Warn($"[IMAP] 复制 {message.Id} 失败：{ex.Message}");
            }
        }
        await OkAsync(writer, tag, "COPY completed");
    }

    private async Task ExpungeAsync(StreamWriter writer, string tag)
    {
        if (selected is null) { await NoAsync(writer, tag, "No mailbox selected"); return; }

        // EXPUNGE 的序号必须随删除动态变化，因此按序号从小到大处理
        var items = store.ListForImap(user!, selected).ToList();
        var index = 0;
        while (index < items.Count)
        {
            var message = items[index];
            if (deleted.Contains(message.Id))
            {
                store.Expunge(user!, message.Id);
                deleted.Remove(message.Id);
                items.RemoveAt(index);
                await WriteAsync(writer, $"* {index + 1} EXPUNGE");
                continue;
            }
            index++;
        }
        await OkAsync(writer, tag, "EXPUNGE completed");
    }

    private async Task AppendAsync(StreamWriter writer, string tag, string rest, CancellationToken token)
    {
        var parts = SplitTokens(rest);
        if (parts.Count == 0) { await NoAsync(writer, tag, "APPEND requires mailbox"); return; }

        var folder = MailFolders.Normalize(parts[0]);
        var literalIndex = rest.LastIndexOf('{');
        if (folder is null || literalIndex < 0) { await NoAsync(writer, tag, "APPEND syntax error"); return; }

        var closing = rest.IndexOf('}', literalIndex);
        if (closing < 0 || !int.TryParse(rest[(literalIndex + 1)..closing], out var size) || size < 0 || size > config.Smtp.MaxMessageBytes)
        {
            await NoAsync(writer, tag, "APPEND invalid literal size");
            return;
        }

        await WriteAsync(writer, "+ Ready for literal data");
        var raw = await reader.ReadExactlyAsync(size, token);
        var flagsArea = rest[..literalIndex].ToUpperInvariant();
        var seen = flagsArea.Contains("\\SEEN");
        var message = store.Append(user!, folder, raw, seen);
        AppLog.Info($"[IMAP] {user} APPEND 到 {folder}：{message?.Subject}");
        await OkAsync(writer, tag, "APPEND completed");
    }

    private async Task IdleAsync(StreamWriter writer, string tag, CancellationToken token)
    {
        await WriteAsync(writer, "+ idling");
        var lastCounts = SnapshotCounts();
        var deadline = DateTimeOffset.UtcNow.AddMinutes(30);

        while (DateTimeOffset.UtcNow < deadline && !token.IsCancellationRequested)
        {
            // 等待客户端发送 DONE：用带超时的读取探测
            var readTask = reader.ReadLineAsync(token);
            var completed = await Task.WhenAny(readTask, Task.Delay(2000, token));
            if (completed == readTask)
            {
                var line = await readTask;
                if (line is null) return;
                if (line.Trim().Equals("DONE", StringComparison.OrdinalIgnoreCase)) break;
                continue;
            }

            var current = SnapshotCounts();
            foreach (var (folder, count) in current)
            {
                if (lastCounts.TryGetValue(folder, out var previous) && previous != count)
                {
                    if (selected is not null && folder == selected)
                        await WriteAsync(writer, $"* {count} EXISTS");
                    else
                        await WriteAsync(writer, $"* OK [STATUS] {DisplayName(folder)} changed");
                }
            }
            lastCounts = current;
        }

        await OkAsync(writer, tag, "IDLE terminated");
    }

    private Dictionary<string, int> SnapshotCounts()
    {
        var map = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var folder in MailFolders.ImapFolders)
            map[folder] = store.ListForImap(user!, folder).Count;
        return map;
    }

    // ---------------------------------------------------------------- 渲染辅助

    private static string DisplayName(string folder) => folder switch
    {
        "inbox" => "INBOX",
        "sent" => "Sent",
        "drafts" => "Drafts",
        "archive" => "Archive",
        "trash" => "Trash",
        "spam" => "Junk",
        _ => folder,
    };

    private static string FlagsOf(MailMessage message)
    {
        var flags = new List<string>();
        if (!message.Unread) flags.Add("\\Seen");
        if (message.Starred) flags.Add("\\Flagged");
        return "(" + string.Join(" ", flags) + ")";
    }

    private static string FormatInternalDate(DateTimeOffset value) =>
        value.ToString("dd-MMM-yyyy HH:mm:ss ", CultureInfo.InvariantCulture) +
        (value.Offset < TimeSpan.Zero ? "-" : "+") +
        value.Offset.Duration().ToString("hhmm", CultureInfo.InvariantCulture);

    private static int IndexOf(IReadOnlyList<MailMessage> items, MailMessage message)
    {
        for (var i = 0; i < items.Count; i++) if (ReferenceEquals(items[i], message) || items[i].Id == message.Id) return i;
        return 0;
    }

    private static bool Matches(string spec, string token) =>
        spec.Contains(token, StringComparison.OrdinalIgnoreCase);

    /// <summary>按「独立 token」匹配 FETCH 项，避免 "RFC822.SIZE" 被当成 "RFC822"。</summary>
    private static bool HasToken(string spec, string token)
    {
        var upper = spec.ToUpperInvariant();
        var needle = token.ToUpperInvariant();
        var index = 0;
        while ((index = upper.IndexOf(needle, index, StringComparison.Ordinal)) >= 0)
        {
            var beforeOk = index == 0 || " ()".IndexOf(upper[index - 1]) >= 0;
            var end = index + needle.Length;
            var afterOk = end >= upper.Length || " ()".IndexOf(upper[end]) >= 0;
            if (beforeOk && afterOk) return true;
            index = end;
        }
        return false;
    }

    private static bool SpecNeedsBodyStructure(string spec)
    {
        var upper = spec.ToUpperInvariant();
        return upper.Contains("BODYSTRUCTURE") || (upper.Contains("BODY") && !upper.Contains("BODY[") && !upper.Contains("BODY.PEEK"));
    }

    /// <summary>从 FETCH 项里取出 BODY[...] / BODY.PEEK[...] 的 section，并判断是否 PEEK。</summary>
    private static (string Section, bool Peek, string Label, string[] Fields)? ExtractBodyItem(string spec)
    {
        var upper = spec.ToUpperInvariant();
        var peekIndex = upper.IndexOf("BODY.PEEK[", StringComparison.Ordinal);
        var plainIndex = peekIndex < 0 ? upper.IndexOf("BODY[", StringComparison.Ordinal) : -1;
        var start = peekIndex >= 0 ? peekIndex : plainIndex;
        if (start < 0) return null;

        var open = spec.IndexOf('[', start);
        // HEADER.FIELDS 的括号里还有括号，必须找到与之配对的 ']'
        var depth = 0;
        var close = -1;
        for (var i = open; i >= 0 && i < spec.Length; i++)
        {
            if (spec[i] == '[') depth++;
            else if (spec[i] == ']')
            {
                depth--;
                if (depth == 0) { close = i; break; }
            }
        }
        if (open < 0 || close < 0) return null;

        var original = spec[(open + 1)..close].Trim();
        // 回显客户端请求的原始 section（客户端按标签匹配，不能改写）
        var label = "BODY[" + original + "]";
        var normalized = NormalizeSection(original);
        var fields = normalized == "HEADER.FIELDS" ? ExtractFieldNames(original) : Array.Empty<string>();
        return (normalized, peekIndex >= 0, label, fields);
    }

    /// <summary>从 HEADER.FIELDS (A B C) 里取出字段名。</summary>
    private static string[] ExtractFieldNames(string section)
    {
        var open = section.IndexOf('(');
        var close = section.LastIndexOf(')');
        if (open < 0 || close <= open) return [];
        return section[(open + 1)..close].Split(' ', StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToArray();
    }

    /// <summary>把客户端请求的 section 归一化；我们的存储是整封原始报文，多数情况返回整封或头部。</summary>
    private static string NormalizeSection(string section)
    {
        var value = section.Trim();
        if (value.Length == 0) return "";
        if (value.StartsWith("HEADER.FIELDS", StringComparison.OrdinalIgnoreCase)) return "HEADER.FIELDS";
        if (value.StartsWith("HEADER", StringComparison.OrdinalIgnoreCase)) return "HEADER";
        if (value.StartsWith("TEXT", StringComparison.OrdinalIgnoreCase)) return "TEXT";
        return "FULL";
    }

    /// <summary>按 section 渲染字节内容。</summary>
    private byte[] SafeReadRaw(MailMessage message)
    {
        try { return store.ReadRaw(message.RawPath); }
        catch { return []; }
    }

    private byte[] RenderSection(MailMessage message, string section, string[] fields)
    {
        var raw = SafeReadRaw(message);
        if (raw.Length == 0)
            raw = Encoding.UTF8.GetBytes($"From: {message.From}{Crlf}To: {message.To}{Crlf}Subject: {message.Subject}{Crlf}{Crlf}{message.Text}");

        var text = Encoding.Latin1.GetString(raw);
        var separator = text.IndexOf("\r\n\r\n", StringComparison.Ordinal);
        var header = separator >= 0 ? text[..(separator + 4)] : text;
        var body = separator >= 0 ? text[(separator + 4)..] : "";

        return section switch
        {
            "HEADER" => Encoding.Latin1.GetBytes(header),
            "HEADER.FIELDS" => Encoding.Latin1.GetBytes(FilterHeaderFields(header, fields)),
            "TEXT" => Encoding.Latin1.GetBytes(body),
            _ => raw,
        };
    }

    private static string FilterHeaderFields(string header, string[] requested)
    {
        var wanted = requested.Length > 0
            ? requested
            : new[] { "From", "To", "Cc", "Subject", "Date", "Message-ID", "Content-Type", "Content-Transfer-Encoding", "MIME-Version" };
        var builder = new StringBuilder();
        foreach (var line in header.Split("\r\n"))
        {
            var colon = line.IndexOf(':');
            if (colon > 0 && wanted.Contains(line[..colon].Trim(), StringComparer.OrdinalIgnoreCase)) builder.Append(line).Append(Crlf);
            else if (line.StartsWith(' ') || line.StartsWith('\t')) { /* 折行忽略 */ }
        }
        return builder.Append(Crlf).ToString();
    }

    private static string Envelope(MailMessage message)
    {
        var date = message.Date.ToString("ddd, dd MMM yyyy HH:mm:ss ", CultureInfo.InvariantCulture) + FormatZone(message.Date);
        var from = AddressList(message.From);
        return $"({Quote(date)} {Quote(Mime.EncodeHeaderValue(message.Subject))} {from} {from} NIL {AddressList(message.To)} {AddressList(message.Cc)} NIL NIL {Quote(message.InReplyTo)} {Quote(message.MessageId)})";
    }

    private static string FormatZone(DateTimeOffset value) =>
        (value.Offset < TimeSpan.Zero ? "-" : "+") + value.Offset.Duration().ToString("hhmm", CultureInfo.InvariantCulture);

    private static string AddressList(string value)
    {
        var addresses = Mime.Addresses(value);
        if (addresses.Length == 0) return "NIL";
        var parts = addresses.Select(a =>
        {
            var at = a.IndexOf('@');
            var mailbox = at > 0 ? a[..at] : a;
            var host = at > 0 ? a[(at + 1)..] : "";
            return $"(NIL NIL {Quote(mailbox)} {Quote(host)})";
        });
        return "(" + string.Join(" ", parts) + ")";
    }

    private static string Quote(string value) => "\"" + (value ?? "").Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"";

    /// <summary>生成 BODYSTRUCTURE。附件在客户端能否正常显示取决于这里是否准确。</summary>
    private string BodyStructure(MailMessage message)
    {
        byte[] raw;
        try { raw = store.ReadRaw(message.RawPath); }
        catch { raw = []; }

        var (headers, body) = Mime.SplitMessage(raw);
        var contentType = headers.FirstOrDefault(h => h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)).Value ?? "";
        var (mediaType, parameters) = Mime.ParseContentType(contentType);
        var transfer = headers.FirstOrDefault(h => h.Key.Equals("Content-Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).Value ?? "7bit";

        if (mediaType.StartsWith("multipart/", StringComparison.OrdinalIgnoreCase) && parameters.TryGetValue("boundary", out var boundary))
        {
            var parts = SplitParts(body, boundary);
            var rendered = parts.Select(p => BodyStructureOfPart(p)).ToList();
            var subtype = mediaType["multipart/".Length..].ToUpperInvariant();
            return "(" + string.Join(" ", rendered) + $" {Quote(subtype)} ({Quote("BOUNDARY")} {Quote(boundary)}))";
        }

        return BodyStructureOfPart((headers, body), mediaType, transfer, forceAttachment: message.Attachments.Count > 0);
    }

    private string BodyStructureOfPart((List<KeyValuePair<string, string>> Headers, byte[] Body) part, string? knownType = null, string? knownTransfer = null, bool forceAttachment = false)
    {
        var contentType = knownType ?? part.Headers.FirstOrDefault(h => h.Key.Equals("Content-Type", StringComparison.OrdinalIgnoreCase)).Value ?? "text/plain; charset=us-ascii";
        var (mediaType, parameters) = Mime.ParseContentType(contentType);
        var transfer = knownTransfer ?? part.Headers.FirstOrDefault(h => h.Key.Equals("Content-Transfer-Encoding", StringComparison.OrdinalIgnoreCase)).Value ?? "7bit";
        var disposition = part.Headers.FirstOrDefault(h => h.Key.Equals("Content-Disposition", StringComparison.OrdinalIgnoreCase)).Value ?? "";
        var (dispType, dispParams) = Mime.ParseContentType(disposition);

        if (mediaType.StartsWith("multipart/", StringComparison.OrdinalIgnoreCase) && parameters.TryGetValue("boundary", out var boundary))
        {
            var parts = SplitParts(part.Body, boundary).Select(p => BodyStructureOfPart(p)).ToList();
            return "(" + string.Join(" ", parts) + $" {Quote(mediaType["multipart/".Length..].ToUpperInvariant())} ({Quote("BOUNDARY")} {Quote(boundary)}))";
        }

        var size = part.Body.Length;
        var lines = part.Body.Count(b => b == (byte)'\n');
        var name = dispParams.GetValueOrDefault("filename") ?? parameters.GetValueOrDefault("name") ?? "";
        var upper = mediaType.ToUpperInvariant();
        var slash = upper.IndexOf('/');
        var main = slash > 0 ? upper[..slash] : upper;
        var sub = slash > 0 ? upper[(slash + 1)..] : "OCTET-STREAM";
        var isText = main == "TEXT";

        var id = parameters.GetValueOrDefault("charset", isText ? "UTF-8" : "");
        var paramList = string.IsNullOrEmpty(id) && string.IsNullOrEmpty(name) ? "NIL" : "(" +
            string.Join(" ", new[]
            {
                isText ? $"{Quote("CHARSET")} {Quote(id.Length > 0 ? id : "UTF-8")}" : "",
                string.IsNullOrEmpty(name) ? "" : $"{Quote("NAME")} {Quote(name)}",
            }.Where(x => x.Length > 0)) + ")";

        var disp = forceAttachment || dispType.Length > 0
            ? $"({Quote(string.IsNullOrEmpty(dispType) ? "ATTACHMENT" : dispType.ToUpperInvariant())} {(string.IsNullOrEmpty(name) ? "NIL" : "(" + Quote("FILENAME") + " " + Quote(name) + ")")})"
            : "NIL";

        var tail = isText
            ? $"{Quote(main)} {Quote(sub)} {paramList} NIL NIL {Quote(transfer.ToUpperInvariant())} {size} {lines}"
            : $"{Quote(main)} {Quote(sub)} {paramList} NIL NIL {Quote(transfer.ToUpperInvariant())} {size}";

        return isText ? $"({tail})" : $"({tail} {disp})";
    }

    private static List<(List<KeyValuePair<string, string>> Headers, byte[] Body)> SplitParts(byte[] body, string boundary)
    {
        var result = new List<(List<KeyValuePair<string, string>>, byte[])>();
        var delimiter = Encoding.ASCII.GetBytes("--" + boundary);
        var positions = new List<int>();
        for (var i = 0; i + delimiter.Length <= body.Length; i++)
        {
            if (body[i] != (byte)'-') continue;
            var match = true;
            for (var j = 0; j < delimiter.Length; j++) if (body[i + j] != delimiter[j]) { match = false; break; }
            if (match) { positions.Add(i); i += delimiter.Length - 1; }
        }
        for (var index = 0; index < positions.Count - 1; index++)
        {
            var start = positions[index];
            var lineEnd = Array.IndexOf(body, (byte)'\n', start);
            if (lineEnd < 0) continue;
            start = lineEnd + 1;
            var end = positions[index + 1];
            while (end > start && (body[end - 1] == (byte)'\n' || body[end - 1] == (byte)'\r')) end--;
            if (end > start) result.Add(Mime.SplitMessage(body[start..end]));
        }
        return result;
    }

    // ---------------------------------------------------------------- 集合与解析

    private static List<MailMessage> ResolveSet(string set, IReadOnlyList<MailMessage> items, bool useUid)
    {
        var result = new List<MailMessage>();
        foreach (var token in set.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var range = token.Split(':', 2);
            if (range.Length == 1)
            {
                var item = Resolve(range[0], items, useUid);
                if (item is not null) result.Add(item);
                continue;
            }

            var start = ResolveIndex(range[0], items, useUid);
            var end = ResolveIndex(range[1], items, useUid);
            if (start < 0 || end < 0) continue;
            if (start > end) (start, end) = (end, start);
            for (var i = start; i <= end && i < items.Count; i++) result.Add(items[i]);
        }
        return result;
    }

    private static int ResolveIndex(string token, IReadOnlyList<MailMessage> items, bool useUid)
    {
        if (token.Trim() == "*") return items.Count - 1;
        if (!int.TryParse(token.Trim(), out var value)) return -1;
        if (!useUid) return value - 1;
        for (var i = 0; i < items.Count; i++) if (items[i].Uid == value) return i;
        return -1;
    }

    private static MailMessage? Resolve(string token, IReadOnlyList<MailMessage> items, bool useUid)
    {
        var index = ResolveIndex(token, items, useUid);
        return index >= 0 && index < items.Count ? items[index] : null;
    }

    private static HashSet<int> ParseUidSet(string set, IReadOnlyList<MailMessage> items)
    {
        var uids = new HashSet<int>();
        foreach (var token in set.Split(',', StringSplitOptions.RemoveEmptyEntries))
        {
            var range = token.Split(':', 2);
            if (range.Length == 1)
            {
                if (int.TryParse(range[0], out var single)) uids.Add(single);
                continue;
            }
            if (!int.TryParse(range[0], out var start)) continue;
            var end = range[1] == "*" ? items.Select(x => x.Uid).DefaultIfEmpty(0).Max() : (int.TryParse(range[1], out var parsed) ? parsed : start);
            if (start > end) (start, end) = (end, start);
            for (var i = start; i <= end; i++) uids.Add(i);
        }
        return uids;
    }

    private static List<string> SplitTokens(string value)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        var depth = 0;
        var quoted = false;
        foreach (var c in value)
        {
            if (c == '"') quoted = !quoted;
            if (!quoted)
            {
                if (c == '(') depth++;
                if (c == ')') depth--;
                if (c == ' ' && depth == 0)
                {
                    if (current.Length > 0) { tokens.Add(current.ToString()); current.Clear(); }
                    continue;
                }
            }
            current.Append(c);
        }
        if (current.Length > 0) tokens.Add(current.ToString());
        return tokens;
    }

    private static string ExtractMailbox(string rest)
    {
        var tokens = SplitTokens(rest);
        return tokens.Count == 0 ? "" : tokens[^1].Trim('"');
    }

    private static string Unquote(string value) => value.Trim().Trim('"');

    private static (string User, string Password) ParseLogin(string rest)
    {
        var tokens = SplitTokens(rest);
        if (tokens.Count < 3) return ("", "");
        return (Unquote(tokens[1]), Unquote(tokens[2]));
    }

    private static bool TryParsePlain(string payload, out string user, out string password)
    {
        user = "";
        password = "";
        try
        {
            var bytes = Convert.FromBase64String(payload.Trim());
            var parts = Encoding.UTF8.GetString(bytes).Split('\0');
            if (parts.Length < 3) return false;
            user = parts[1];
            password = parts[2];
            return true;
        }
        catch { return false; }
    }

    // ---------------------------------------------------------------- 输出

    /// <summary>写出响应。注意：未标记响应必须自带 "* " 前缀，标记响应由调用方拼接 tag。</summary>
    private static Task WriteAsync(StreamWriter writer, string line) =>
        writer.WriteLineAsync(line);

    private static Task OkAsync(StreamWriter writer, string tag, string text) =>
        writer.WriteLineAsync($"{tag} OK {text}");

    private static Task NoAsync(StreamWriter writer, string tag, string text) =>
        writer.WriteLineAsync($"{tag} NO {text}");

    private static async Task WriteBytesAsync(StreamWriter writer, byte[] data)
    {
        await writer.FlushAsync();
        await writer.BaseStream.WriteAsync(data);
        await writer.BaseStream.FlushAsync();
    }
}
