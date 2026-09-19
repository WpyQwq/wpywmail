using System.Text;

namespace WpywMail.Native;

/// <summary>
/// 入站校验（SPF / DKIM / DMARC）自检。
///
/// 关键设计：**DNS 查询走固定记录的桩实现**，所以断言是确定性的、不依赖外网。
/// 而 DKIM 部分特意包含「篡改必须失败」的反向用例 —— 2026-09-13 的 DKIM 事故就是
/// 「验签和签名犯了同一个错，于是一直假通过」，任何验签实现都必须能被打假才算数。
/// </summary>
public static partial class SelfTest
{
    private sealed class StubDns : IDnsLookup
    {
        public readonly Dictionary<string, string[]> Txt = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string[]> Addresses = new(StringComparer.OrdinalIgnoreCase);
        public readonly Dictionary<string, string[]> Mx = new(StringComparer.OrdinalIgnoreCase);

        public Task<IReadOnlyList<string>> TxtAsync(string name, CancellationToken token) =>
            Task.FromResult<IReadOnlyList<string>>(Txt.TryGetValue(name, out var v) ? v : []);
        public Task<IReadOnlyList<string>> AddressesAsync(string name, CancellationToken token) =>
            Task.FromResult<IReadOnlyList<string>>(Addresses.TryGetValue(name, out var v) ? v : []);
        public Task<IReadOnlyList<string>> MxAsync(string name, CancellationToken token) =>
            Task.FromResult<IReadOnlyList<string>>(Mx.TryGetValue(name, out var v) ? v : []);
    }

    private static void TestInboundAuth()
    {
        var config = new AppConfig
        {
            Domain = "wpy.email",
            Hostname = "mail.example.com",
            AdminEmail = "wpy@wpy.email",
            AdminPassword = "SelfTest-Password-12",
            DataDirectory = Path.Combine(Path.GetTempPath(), $"wpyw-auth-{Guid.NewGuid().ToString("N")[..8]}"),
            Dkim = new DkimConfig { Enabled = true, Selector = "sel" },
            InboundAuth = new InboundAuthConfig { DnsTimeoutSeconds = 2 },
        };
        Directory.CreateDirectory(config.DataDirectory);

        try
        {
            var dns = new StubDns();
            var token = CancellationToken.None;
            var cfg = config.InboundAuth;

            // ─────────────────────────── SPF
            dns.Txt["strict.example.com"] = ["v=spf1 ip4:203.0.113.0/24 -all"];
            var pass = Spf.EvaluateAsync("203.0.113.5", "mail.example.com", "bob@strict.example.com", dns, cfg, token).Result;
            Check("SPF：ip4 CIDR 命中 → pass", pass.Outcome == "pass", $"{pass.Outcome} {pass.Detail}");

            var fail = Spf.EvaluateAsync("198.51.100.7", "mail.example.com", "bob@strict.example.com", dns, cfg, token).Result;
            Check("SPF：ip4 不命中且 -all → fail", fail.Outcome == "fail", $"{fail.Outcome} {fail.Detail}");

            dns.Txt["soft.example.com"] = ["v=spf1 ~all"];
            var soft = Spf.EvaluateAsync("198.51.100.7", "x", "bob@soft.example.com", dns, cfg, token).Result;
            Check("SPF：~all → softfail", soft.Outcome == "softfail", soft.Outcome);

            dns.Txt["neutral.example.com"] = ["v=spf1 ?all"];
            var neutral = Spf.EvaluateAsync("198.51.100.7", "x", "bob@neutral.example.com", dns, cfg, token).Result;
            Check("SPF：?all → neutral", neutral.Outcome == "neutral", neutral.Outcome);

            dns.Txt["inc.example.com"] = ["v=spf1 include:_spf.relay.net -all"];
            dns.Txt["_spf.relay.net"] = ["v=spf1 ip4:198.51.100.7 -all"];
            var included = Spf.EvaluateAsync("198.51.100.7", "x", "bob@inc.example.com", dns, cfg, token).Result;
            Check("SPF：include 命中 → pass", included.Outcome == "pass", included.Detail);

            dns.Txt["inc2.example.com"] = ["v=spf1 include:_spf.other.net -all"];
            dns.Txt["_spf.other.net"] = ["v=spf1 ip4:203.0.113.1 -all"];
            var notIncluded = Spf.EvaluateAsync("198.51.100.7", "x", "bob@inc2.example.com", dns, cfg, token).Result;
            Check("SPF：include 不命中 → 落到 -all 的 fail", notIncluded.Outcome == "fail", notIncluded.Outcome);

            dns.Txt["a.example.com"] = ["v=spf1 a -all"];
            dns.Addresses["a.example.com"] = ["198.51.100.7"];
            var aMatch = Spf.EvaluateAsync("198.51.100.7", "x", "bob@a.example.com", dns, cfg, token).Result;
            Check("SPF：a 机制按 A 记录命中", aMatch.Outcome == "pass", aMatch.Outcome);

            dns.Txt["mx.example.com"] = ["v=spf1 mx -all"];
            dns.Mx["mx.example.com"] = ["mx1.example.com"];
            dns.Addresses["mx1.example.com"] = ["198.51.100.7"];
            var mxMatch = Spf.EvaluateAsync("198.51.100.7", "x", "bob@mx.example.com", dns, cfg, token).Result;
            Check("SPF：mx 机制按 MX 主机命中", mxMatch.Outcome == "pass", mxMatch.Outcome);

            var missing = Spf.EvaluateAsync("198.51.100.7", "x", "bob@nospf.example.com", dns, cfg, token).Result;
            Check("SPF：没有记录 → none", missing.Outcome == "none", missing.Outcome);

            dns.Txt["dup.example.com"] = ["v=spf1 -all", "v=spf1 +all"];
            var dup = Spf.EvaluateAsync("198.51.100.7", "x", "bob@dup.example.com", dns, cfg, token).Result;
            Check("SPF：两条记录 → permerror", dup.Outcome == "permerror", dup.Outcome);

            // 查询次数上限：链式 include 超过 10 次必须 permerror
            for (var i = 0; i < 14; i++)
                dns.Txt[$"chain{i}.example.com"] = [$"v=spf1 include:chain{i + 1}.example.com -all"];
            dns.Txt["chain14.example.com"] = ["v=spf1 ip4:203.0.113.9 -all"];
            var tooMany = Spf.EvaluateAsync("198.51.100.7", "x", "bob@chain0.example.com", dns, cfg, token).Result;
            Check("SPF：include 链超过 10 次查询 → permerror", tooMany.Outcome == "permerror", tooMany.Outcome);

            var heloFallback = Spf.EvaluateAsync("198.51.100.7", "helo.example.com", "", dns, cfg, token).Result;
            Check("SPF：空 MAIL FROM 时回退用 HELO 域", heloFallback.Domain == "helo.example.com", heloFallback.Domain);

            Check("SPF：组织域/宏展开",
                Spf.DomainOf("Bob <bob@Example.COM>") == "example.com"
                && Spf.Expand("%{d}/%{o}/%{l}", "ex.com", System.Net.IPAddress.Parse("1.2.3.4"), "bob@ex.com", "h") == "ex.com/ex.com/bob",
                Spf.Expand("%{d}/%{o}/%{l}", "ex.com", System.Net.IPAddress.Parse("1.2.3.4"), "bob@ex.com", "h"));

            // ─────────────────────────── DKIM（用本机签名器造真实签名，再打假）
            var signer = DkimSigner.Create(config);
            Check("DKIM：签名器可用（自检用）", signer is not null, "未启用则跳过后面的验签");
            if (signer is not null)
            {
                var raw = BuildMessage("from@dkim.example.com", "收件人", "DKIM self-test 主题", "line-one ASCII marker\r\n第二行。\r\n");
                var signed = signer.Sign(raw);
                dns.Txt[signer.RecordName + "." + config.Domain] = [signer.RecordValue];

                var okResult = DkimVerifier.VerifyAllAsync(signed, dns, token).Result;
                Check("DKIM：自己签的报文验签通过", okResult.Count == 1 && okResult[0].Outcome == "pass",
                    okResult.Count == 0 ? "(没找到签名)" : $"{okResult[0].Outcome} {okResult[0].Detail}");

                // 反向用例 1：改正文（用 ASCII 标记改，避免在 Latin1 视图里搜中文搜不到）
                var bad1 = DkimVerifier.VerifyAllAsync(Tamper(signed, "line-one ASCII marker", "line-one TAMPERED"), dns, token).Result;
                Check("DKIM：改正文后必须验签失败", bad1.Count > 0 && bad1[0].Outcome == "fail",
                    bad1.Count == 0 ? "(没找到签名)" : bad1[0].Detail);

                // 反向用例 2：改被签名的头（同样只能用 ASCII 片段做替换 —— Latin1 视图里搜不到 UTF-8 中文）
                var bad2 = DkimVerifier.VerifyAllAsync(Tamper(signed, "DKIM self-test", "DKIM tampered!!"), dns, token).Result;
                Check("DKIM：改主题后必须验签失败", bad2.Count > 0 && bad2[0].Outcome == "fail",
                    bad2.Count == 0 ? "(没找到签名)" : bad2[0].Detail);

                // 反向用例 2b：只翻转正文里的一个字节也必须失败（最严格的篡改用例）
                var flipped = (byte[])signed.Clone();
                var marker = Encoding.Latin1.GetBytes("line-one ASCII marker");
                var at = IndexOf(flipped, marker);
                if (at > 0) flipped[at + 3] ^= 0x01;
                var bad2b = DkimVerifier.VerifyAllAsync(flipped, dns, token).Result;
                Check("DKIM：正文翻转一个字节必须验签失败", at > 0 && bad2b.Count > 0 && bad2b[0].Outcome == "fail",
                    at > 0 ? bad2b[0].Detail : "测试标记没找到");

                // 反向用例 3：DNS 里换成别人的公钥
                var otherConfig = new AppConfig
                {
                    Domain = config.Domain, Hostname = config.Hostname, AdminEmail = config.AdminEmail,
                    AdminPassword = config.AdminPassword, DataDirectory = config.DataDirectory,
                    Dkim = new DkimConfig { Enabled = true, Selector = "other" },
                };
                var other = DkimSigner.Create(otherConfig);
                dns.Txt[signer.RecordName + "." + config.Domain] = [other!.RecordValue];
                var bad3 = DkimVerifier.VerifyAllAsync(signed, dns, token).Result;
                Check("DKIM：公钥不匹配必须验签失败", bad3.Count > 0 && bad3[0].Outcome == "fail",
                    bad3.Count == 0 ? "(没找到签名)" : bad3[0].Detail);

                // 反向用例 4：公钥被吊销（p= 为空）
                dns.Txt[signer.RecordName + "." + config.Domain] = ["v=DKIM1; k=rsa; p="];
                var bad4 = DkimVerifier.VerifyAllAsync(signed, dns, token).Result;
                Check("DKIM：公钥 p= 为空（已吊销）→ fail", bad4.Count > 0 && bad4[0].Outcome == "fail",
                    bad4.Count == 0 ? "(没找到签名)" : bad4[0].Detail);
                dns.Txt[signer.RecordName + "." + config.Domain] = [signer.RecordValue];

                // 加前置头（我们入站校验要往报文前面插 Authentication-Results）不能破坏对方签名
                var withHeaders = InboundAuth.PrependHeaders(signed, "Authentication-Results: mail.example.com; spf=pass\r\nX-Spam-Score: 0\r\n");
                var stillOk = DkimVerifier.VerifyAllAsync(withHeaders, dns, token).Result;
                Check("DKIM：前面插入我们自己的头之后，对方签名依然有效",
                    stillOk.Count == 1 && stillOk[0].Outcome == "pass", $"{stillOk.Count} 个签名");

                var plain = DkimVerifier.VerifyAllAsync(BuildMessage("a@b.com", "x", "无签名", "正文"), dns, token).Result;
                Check("DKIM：没有签名的报文返回空列表", plain.Count == 0, $"{plain.Count} 个");
            }

            // ─────────────────────────── DMARC
            dns.Txt["_dmarc.strict2.example.com"] = ["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"];
            var dmarcPass = Dmarc.EvaluateAsync("strict2.example.com", ("pass", "strict2.example.com"), [], dns, token).Result;
            Check("DMARC：SPF 对齐通过 + p=reject", dmarcPass.Outcome == "pass" && dmarcPass.Policy == "reject",
                $"{dmarcPass.Outcome}/{dmarcPass.Policy}");

            var dmarcFail = Dmarc.EvaluateAsync("strict2.example.com", ("fail", "evil.net"), [], dns, token).Result;
            Check("DMARC：SPF 未对齐 → fail 且带策略", dmarcFail.Outcome == "fail" && dmarcFail.Policy == "reject",
                $"{dmarcFail.Outcome}/{dmarcFail.Policy}");

            dns.Txt["_dmarc.relaxed.example.com"] = ["v=DMARC1; p=quarantine"];
            var relaxedAlign = Dmarc.EvaluateAsync("relaxed.example.com", ("pass", "mail.relaxed.example.com"), [], dns, token).Result;
            Check("DMARC：relaxed 对齐（子域算对齐）→ pass", relaxedAlign.Outcome == "pass", relaxedAlign.Detail);

            dns.Txt["_dmarc.strictdomain.example.com"] = ["v=DMARC1; p=none; aspf=s"];
            var strictAlign = Dmarc.EvaluateAsync("strictdomain.example.com", ("pass", "mail.strictdomain.example.com"), [], dns, token).Result;
            Check("DMARC：aspf=s 时子域不算对齐 → fail", strictAlign.Outcome == "fail", strictAlign.Detail);

            var dmarcDkim = Dmarc.EvaluateAsync("dkimalign.example.com", ("fail", "x"), [("pass", "dkimalign.example.com")],
                new StubDnsWithRecords(("_dmarc.dkimalign.example.com", "v=DMARC1; p=none")), token).Result;
            Check("DMARC：SPF 挂了但 DKIM 对齐 → 依然 pass", dmarcDkim.Outcome == "pass", dmarcDkim.Detail);

            var noRecord = Dmarc.EvaluateAsync("nodmarc.example.com", ("fail", "x"), [], dns, token).Result;
            Check("DMARC：没有记录 → none", noRecord.Outcome == "none", noRecord.Outcome);

            Check("DMARC：组织域判定（含 com.cn/co.uk 这类多段后缀）",
                Dmarc.OrganizationalDomain("a.b.example.co.uk") == "example.co.uk"
                && Dmarc.OrganizationalDomain("mail.example.com") == "example.com"
                && Dmarc.OrganizationalDomain("news.sina.com.cn") == "sina.com.cn",
                Dmarc.OrganizationalDomain("a.b.example.co.uk"));

            // ─────────────────────────── 端到端：干净信 vs 冒名信
            var cleanDns = new StubDns();
            if (signer is not null)
            {
                var cleanRaw = signer.Sign(BuildMessage("boss@wpy.email", "我", "正常邮件", "正文内容\r\n"));
                cleanDns.Txt[signer.RecordName + "." + config.Domain] = [signer.RecordValue];
                cleanDns.Txt["_dmarc." + config.Domain] = ["v=DMARC1; p=reject"];
                cleanDns.Txt[config.Domain] = ["v=spf1 ip4:203.0.113.0/24 -all"];

                var clean = InboundAuth.CheckAsync(cleanRaw, "203.0.113.9", "mail.example.com", "boss@wpy.email", config, token, cleanDns).Result;
                Check("端到端：SPF+DKIM+DMARC 全通过的邮件不判垃圾",
                    clean.Spf == "pass" && clean.Dkim == "pass" && clean.Dmarc == "pass" && clean.Score == 0 && !clean.Spam,
                    $"spf={clean.Spf} dkim={clean.Dkim} dmarc={clean.Dmarc} 分数={clean.Score}");
                Check("端到端：Authentication-Results 头写全了",
                    clean.HeaderBlock.Contains("spf=pass") && clean.HeaderBlock.Contains("dkim=pass")
                    && clean.HeaderBlock.Contains("dmarc=pass") && clean.HeaderBlock.Contains("X-Spam-Score: 0"),
                    clean.HeaderBlock.Replace("\r\n", " | ").Trim());

                // 冒名信：外域 IP 假冒 wpy.email，无 DKIM，DMARC p=reject
                var spoof = InboundAuth.CheckAsync(BuildMessage("boss@wpy.email", "我", "我是老板", "把钱转过来"),
                    "198.51.100.7", "evil.example.net", "boss@wpy.email", config, token, cleanDns).Result;
                Check("端到端：冒名邮件被判为垃圾（SPF fail + DMARC 失败）",
                    spoof.Spf == "fail" && spoof.Dmarc == "fail" && spoof.Spam && spoof.Score >= 4,
                    $"spf={spoof.Spf} dmarc={spoof.Dmarc} 分数={spoof.Score} 垃圾={spoof.Spam}");
                Check("端到端：默认不拒收（只投垃圾箱，可逆）", !spoof.Reject, $"Reject={spoof.Reject}");

                var strictConfig = new AppConfig
                {
                    Domain = config.Domain, Hostname = config.Hostname, AdminEmail = config.AdminEmail,
                    AdminPassword = config.AdminPassword, DataDirectory = config.DataDirectory,
                    Dkim = config.Dkim,
                    InboundAuth = new InboundAuthConfig { RejectOnDmarcReject = true },
                };
                var strictSpoof = InboundAuth.CheckAsync(BuildMessage("boss@wpy.email", "我", "我是老板", "把钱转过来"),
                    "198.51.100.7", "evil.example.net", "boss@wpy.email", strictConfig, token, cleanDns).Result;
                Check("端到端：打开 RejectOnDmarcReject 后 p=reject 的冒名信会被拒收", strictSpoof.Reject, $"Reject={strictSpoof.Reject}");

                // 插入头之后报文仍可正常解析（不能把收信搞坏）
                var withAuth = InboundAuth.PrependHeaders(cleanRaw, clean.HeaderBlock);
                var reparsed = Mime.Parse(withAuth);
                Check("端到端：插入校验头后报文仍能正常解析",
                    reparsed.Subject == "正常邮件" && reparsed.Text.Contains("正文内容"), $"{reparsed.Subject} / {reparsed.Text.Trim()}");
            }

            Check("端到端：X-Spam-Reason 会说明判垃圾的理由",
                InboundAuth.CheckAsync(BuildMessage("boss@wpy.email", "我", "x", "y"),
                    "198.51.100.7", "evil.example.net", "boss@wpy.email", config, token, cleanDns).Result
                    .HeaderBlock.Contains("X-Spam-Reason:"), "");
        }
        catch (Exception ex)
        {
            Fail("入站校验自检", $"抛出异常：{ex}");
        }
        finally
        {
            try { Directory.Delete(config.DataDirectory, true); } catch { }
        }
    }

    /// <summary>只带一条 DNS 记录的一次性桩（用于个别用例）。</summary>
    private sealed class StubDnsWithRecords(params (string Name, string Value)[] records) : IDnsLookup
    {
        public Task<IReadOnlyList<string>> TxtAsync(string name, CancellationToken token) =>
            Task.FromResult<IReadOnlyList<string>>(records.Where(r => r.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                .Select(r => r.Value).ToArray());
        public Task<IReadOnlyList<string>> AddressesAsync(string name, CancellationToken token) => Task.FromResult<IReadOnlyList<string>>([]);
        public Task<IReadOnlyList<string>> MxAsync(string name, CancellationToken token) => Task.FromResult<IReadOnlyList<string>>([]);
    }

    /// <summary>在字节层面做替换（用 Latin1 视图，1 字符 = 1 字节，不会动到别的字节）。</summary>
    private static byte[] Tamper(byte[] raw, string from, string to) =>
        Encoding.Latin1.GetBytes(Encoding.Latin1.GetString(raw).Replace(from, to));

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i + needle.Length <= haystack.Length; i++)
        {
            var hit = true;
            for (var j = 0; j < needle.Length; j++)
                if (haystack[i + j] != needle[j]) { hit = false; break; }
            if (hit) return i;
        }
        return -1;
    }

    private static byte[] BuildMessage(string from, string toName, string subject, string body)
    {
        var text = $"From: <{from}>\r\nTo: <wpy@wpy.email>\r\nSubject: {subject}\r\n"
                 + $"Date: {Mime.FormatDate(DateTimeOffset.Now)}\r\nMessage-ID: <{Guid.NewGuid():N}@example.com>\r\n"
                 + "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n"
                 + "Content-Transfer-Encoding: 8bit\r\n\r\n" + body;
        return Encoding.UTF8.GetBytes(text);
    }
}
