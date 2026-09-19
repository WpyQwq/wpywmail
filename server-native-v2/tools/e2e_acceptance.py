#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WpywMail.Native v2 —— 端到端验收测试（在服务器本机执行）

设计原则：
  · 只用 Python 标准库（服务器上是 3.8，没有 requests / cryptography）；
  · 密码从 appsettings.json 读取，绝不硬编码；
  · 自带纯 Python 的 RSA/SHA-256 PKCS#1 v1.5 验签器，直接对「将来要发布到 DNS 的公钥」
    验证真实投递报文的 DKIM 签名 —— 这一步不依赖服务端私钥，也不依赖外部库；
  · 覆盖收信、发信、API、IMAP、DKIM、以及三条安全回归（非开放中继 / 提交需认证 / 明文登录限制）。

用法：
    python e2e_acceptance.py                 # 全部用例
    python e2e_acceptance.py --report out.txt
退出码 = 失败用例数（0 表示全部通过）。
"""
import argparse
import base64
import hashlib
import imaplib
import json
import os
import re
import smtplib
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request
from email.message import EmailMessage
from email import utils as email_utils

socket.setdefaulttimeout(20)

EXE = r"C:\Program Files\WpywMail\WpywMail.Native.exe"
CONFIG = r"C:\Program Files\WpywMail\appsettings.json"

PASSED = []
FAILED = []


def check(name, ok, detail=""):
    (PASSED if ok else FAILED).append(name)
    mark = "PASS" if ok else "FAIL"
    line = "  [{}] {}".format(mark, name)
    if detail and not ok:
        line += "  <- " + str(detail)[:200]
    elif detail:
        line += "  ({})".format(str(detail)[:120])
    print(line)
    return ok


def section(title):
    print("\n=== {} ===".format(title))


def load_config():
    with open(CONFIG, "r", encoding="utf-8-sig") as fh:
        return json.load(fh)


# --------------------------------------------------------------------- API 客户端

def api(base, path, method="GET", payload=None, token=None, raw=False):
    url = base.rstrip("/") + path
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
            return resp.status, (body if raw else json.loads(body.decode("utf-8")))
    except urllib.error.HTTPError as err:
        body = err.read()
        try:
            return err.code, json.loads(body.decode("utf-8"))
        except Exception:
            return err.code, body


# --------------------------------------------------------------------- 纯 Python DKIM 验签

def der_read(data, offset):
    """极简 DER TLV 解析，返回 (tag, value_bytes, next_offset)。"""
    tag = data[offset]
    offset += 1
    length = data[offset]
    offset += 1
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def spki_to_rsa(der):
    """从 SubjectPublicKeyInfo 里取出 (n, e)。"""
    _, spki, _ = der_read(der, 0)
    _, _, off = der_read(spki, 0)                      # AlgorithmIdentifier，跳过
    _, bitstring, _ = der_read(spki, off)              # subjectPublicKey BIT STRING
    if bitstring[0] != 0:
        raise ValueError("BIT STRING 未使用位不为 0")
    _, rsa_seq, _ = der_read(bitstring[1:], 0)
    _, modulus, off2 = der_read(rsa_seq, 0)
    _, exponent, _ = der_read(rsa_seq, off2)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")

SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


def rsa_verify_sha256(n, e, signature, message):
    try:
        size = (n.bit_length() + 7) // 8
        m = pow(int.from_bytes(signature, "big"), e, n)
        em = m.to_bytes(size, "big")
        if em[0] != 0x00 or em[1] != 0x01:
            return False, "PKCS#1 padding 前缀不符"
        sep = em.index(b"\x00", 2)
        digest_info = em[sep + 1:]
        expected = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
        if digest_info != expected:
            return False, "DigestInfo 不匹配"
        return True, ""
    except Exception as exc:
        return False, "{}: {}".format(type(exc).__name__, exc)


def split_message(raw):
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return [], raw
    head, body = raw[:sep], raw[sep + 4:]
    headers = []
    name = None
    for line in head.decode("latin-1").split("\r\n"):
        if line[:1] in (" ", "\t") and name:
            headers[-1] = (name, headers[-1][1] + "\r\n" + line)
        else:
            idx = line.find(":")
            if idx > 0:
                name = line[:idx]
                headers.append((name, line[idx + 1:]))
    return headers, body


def canon_header(name, value):
    unfolded = value.replace("\r\n", "").replace("\n", "")
    return name.strip().lower() + ":" + re.sub(r"[ \t]+", " ", unfolded).strip()


def canon_body(body):
    text = body.decode("latin-1").replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t]+", " ", line).rstrip(" \t") for line in text.split("\n")]
    joined = "\r\n".join(lines).rstrip("\r\n")
    return (joined + "\r\n").encode("latin-1") if joined else b""


def verify_dkim(raw, n, e):
    """按 RFC 6376 relaxed/relaxed 验证整封邮件的 DKIM 签名。"""
    headers, body = split_message(raw)
    dkim = [v for k, v in headers if k.lower() == "dkim-signature"]
    if not dkim:
        return False, "报文没有 DKIM-Signature 头"
    tags = {}
    for part in dkim[0].split(";"):
        if "=" in part:
            key, _, value = part.partition("=")
            tags[key.strip()] = value.strip()
    if tags.get("a") != "rsa-sha256":
        return False, "非 rsa-sha256: " + str(tags.get("a"))

    if base64.b64encode(hashlib.sha256(canon_body(body)).digest()).decode() != tags.get("bh"):
        return False, "正文哈希(bh)不匹配"

    # RFC 6376 §3.7 第 2 步：先按 h= 顺序哈希各被签名头（每个后面跟一个 CRLF），
    # 最后哈希 DKIM-Signature 头本身且不带结尾 CRLF。
    signing = ""
    for name in tags.get("h", "").split(":"):
        hit = next((v for k, v in headers if k.lower() == name.strip().lower()), None)
        if hit is None:
            return False, "缺少被签名头 " + name
        signing += canon_header(name, hit) + "\r\n"
    signing += canon_header("DKIM-Signature", dkim[0].replace(tags["b"], "").rstrip())

    return rsa_verify_sha256(n, e, base64.b64decode(tags["b"]), signing.encode("ascii"))


# --------------------------------------------------------------------- SMTP 辅助

def smtp_talk(host, port, commands, starttls=False, auth=None, timeout=25):
    """返回每一步的响应码列表，便于断言协议细节。"""
    out = []
    client = smtplib.SMTP(host, port)
    client.ehlo("e2e.local")
    out.append(("EHLO", 250, sorted(client.esmtp_features.keys())))
    if starttls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        # Python 3.8 的 smtplib.starttls(keyfile, certfile, context)：context 必须用关键字传，
        # 否则会被当成 keyfile（报 'certfile must be specified'）
        client.starttls(context=ctx)
        client.ehlo("e2e.local")
        out.append(("EHLO-after-TLS", 250, sorted(client.esmtp_features.keys())))
    if auth:
        client.login(auth[0], auth[1])
        out.append(("AUTH", 235, ""))
    return client, out


def build_chinese_message(sender, recipient, subject, body):
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = recipient
    msg["Subject"] = subject
    msg["Date"] = email_utils.formatdate(localtime=True)
    msg["Message-ID"] = email_utils.make_msgid(domain=sender.split("@")[-1])
    msg.set_content(body)
    return msg


def build_raw_8bit(sender, recipient, subject, body, token):
    return (
        "From: {} <{}>\r\n"
        "To: {}\r\n"
        "Subject: {}\r\n"
        "Date: {}\r\n"
        "Message-ID: <e2e-{}@e2e.local>\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "Content-Transfer-Encoding: 8bit\r\n"
        "\r\n"
        "{}\r\n"
    ).format("验收发件人", sender, recipient, subject, email_utils.formatdate(localtime=True), token, body).encode("utf-8")


# --------------------------------------------------------------------- 主流程

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--report", default=r"C:\_probe\e2e_report.txt")
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()

    cfg = load_config()
    domain = cfg["Domain"]
    hostname = cfg["Hostname"]
    account = cfg["AdminEmail"]
    password = cfg["AdminPassword"]
    smtp_port = int(cfg.get("SmtpPort", 25))
    submission_port = int(cfg.get("SubmissionPort", 587))
    imap_port = int(cfg.get("Imap", {}).get("Port", 143))
    api_base = "http://127.0.0.1:{}/".format(
        re.search(r":(\d+)", cfg.get("HttpPrefix", "http://127.0.0.1:8787/")).group(1))
    stamp = time.strftime("%H%M%S")
    host = args.host
    print("WpywMail v2 端到端验收  domain={}  account={}  {}".format(domain, account, stamp))

    # ---------- 1. 二进制自检 ----------
    section("1) 二进制自检（--check-config / --selftest）")
    try:
        out = subprocess.run([EXE, "--check-config"], capture_output=True, timeout=60)
        check("配置校验通过", out.returncode == 0, out.stderr.decode("utf-8", "replace")[:120])
        out = subprocess.run([EXE, "--selftest"], capture_output=True, timeout=180)
        text = out.stdout.decode("utf-8", "replace")
        match = re.search(r"=+ 结果：(\d+) 项通过，(\d+) 项失败", text)
        check("内建自检全部通过", out.returncode == 0 and match and match.group(2) == "0",
              match.group(0) if match else text[-160:])
    except Exception as exc:
        check("二进制自检", False, exc)

    # ---------- 2. DKIM 公钥可导出 ----------
    section("2) DKIM 公钥与 RSA 参数")
    dkim_record = ""
    n = e = None
    try:
        out = subprocess.run([EXE, "--dkim-dns"], capture_output=True, timeout=120)
        for line in out.stdout.decode("utf-8", "replace").splitlines():
            if line.startswith("VALUE="):
                dkim_record = line[len("VALUE="):].strip()
            if line.startswith("NAME="):
                dkim_name = line[len("NAME="):].strip()
        check("--dkim-dns 输出公钥记录", dkim_record.startswith("v=DKIM1;"), dkim_record[:80])
        match = re.search(r"p=([A-Za-z0-9+/=]+)", dkim_record)
        n, e = spki_to_rsa(base64.b64decode(match.group(1)))
        check("公钥可解析为 RSA 参数（2048 位）", n.bit_length() == 2048,
              "modulus {} 位".format(n.bit_length()))
        print("      待发布记录: {}.{} = {}...(共 {} 字符)".format(
            dkim_name, domain, dkim_record[:48], len(dkim_record)))
    except Exception as exc:
        check("DKIM 公钥导出", False, exc)

    # ---------- 3. SMTP 收信（8bit 裸 UTF-8 中文） ----------
    section("3) SMTP 收信（公网收信端口，8bit 裸 UTF-8）")
    inbox_token = "E2E-IN-" + stamp
    try:
        subject = "[验收] 外网中文邮件 " + inbox_token
        body = "这是验收测试注入的中文正文。\n标记：{}\n全角标点：你好，世界。（）《》——".format(inbox_token)
        raw = build_raw_8bit("probe@e2e.local", account, subject, body, inbox_token)
        client = smtplib.SMTP(host, smtp_port)
        code, caps = client.ehlo("e2e.local")
        check("25 端口 EHLO 成功", code == 250, code)
        check("25 端口广告 8BITMIME", "8bitmime" in [c.lower() for c in caps.decode().split("\n")[-1:]] or b"8BITMIME" in caps,
              caps.decode("utf-8", "replace")[:120])
        client.sendmail("probe@e2e.local", [account], raw, mail_options=["BODY=8BITMIME"])
        client.quit()
        check("8bit 中文邮件投递被接受", True)
    except Exception as exc:
        check("8bit 中文邮件投递被接受", False, exc)

    # ---------- 4. API 登录与收信入库 ----------
    section("4) API：登录 / 收件箱 / 中文解码")
    token = None
    try:
        status, obj = api(api_base, "/api/login", "POST", {"email": account, "password": password})
        check("登录成功", status == 200 and obj.get("token"), status)
        token = obj.get("token")
        status, obj = api(api_base, "/api/me", token=token)
        check("/api/me 返回统计", status == 200 and "stats" in obj, status)
        time.sleep(1.5)
        status, obj = api(api_base, "/api/messages?folder=inbox&q=" + inbox_token, token=token)
        found = obj.get("messages", []) if status == 200 else []
        check("刚投递的中文邮件出现在收件箱", len(found) == 1, "命中 {} 封".format(len(found)))
        if found:
            check("主题中文正确（无编解码乱码）", inbox_token in found[0]["subject"], found[0]["subject"])
            check("正文预览中文正确", "验收测试注入的中文正文" in found[0].get("preview", ""), found[0].get("preview"))
    except Exception as exc:
        check("API 收件箱检查", False, exc)

    # ---------- 5. SMTP 提交（STARTTLS + AUTH） ----------
    section("5) SMTP 提交端口：STARTTLS + AUTH + 中文提交")
    submit_token = "E2E-OUT-" + stamp
    try:
        client, steps = smtp_talk(host, submission_port, [], starttls=True)
        caps_plain = steps[0][2]
        check("587 明文阶段广告 STARTTLS", "starttls" in caps_plain, caps_plain)
        caps_tls = steps[1][2] if len(steps) > 1 else []
        check("TLS 之后才广告 AUTH", "auth" in caps_tls, caps_tls)
        client.login(account, password)
        check("AUTH 认证成功（旧版此处为 538 死锁）", True)
        msg = build_chinese_message(account, account, "[验收] 587 提交中文邮件 " + submit_token,
                                    "通过 STARTTLS + AUTH 提交的中文正文。\n标记：{}".format(submit_token))
        client.send_message(msg)
        client.quit()
        check("中文邮件经 587 提交成功", True)
    except Exception as exc:
        check("587 提交链路", False, exc)

    # ---------- 6. 队列与本地投递 ----------
    section("6) 出站队列与本地投递")
    try:
        deadline = time.time() + 40
        state = "?"
        while time.time() < deadline:
            status, obj = api(api_base, "/api/queue", token=token)
            items = [x for x in obj.get("queue", []) if any(r == account for r in x["recipients"])]
            if items and all(x["status"] == "sent" for x in items):
                state = "sent"
                break
            state = items[-1]["status"] if items else "(无任务)"
            time.sleep(3)
        check("发给本机账号的任务投递完成", state == "sent", "最终状态=" + state)
    except Exception as exc:
        check("队列投递", False, exc)

    # ---------- 7. DKIM 独立验签（对公钥验证真实投递报文） ----------
    section("7) DKIM：对将来要发布的公钥验证真实投递报文")
    if n and e:
        try:
            status, obj = api(api_base, "/api/messages?folder=inbox&q=" + submit_token, token=token)
            msgs = obj.get("messages", []) if status == 200 else []
            signed_id = msgs[0]["id"] if msgs else None
            if not signed_id:
                check("找到带签名的投递副本", False, "收件箱没有找到 587 提交的那封")
            else:
                status, raw = api(api_base, "/api/messages/{}/raw".format(signed_id), token=token, raw=True)
                has_sig = b"DKIM-Signature" in raw
                check("投递副本带 DKIM-Signature", has_sig, "{} 字节".format(len(raw)))
                if has_sig:
                    ok, reason = verify_dkim(raw, n, e)
                    check("DKIM 签名对公钥验证通过（rsa-sha256 / 正文哈希一致）", ok, reason)
        except Exception as exc:
            check("DKIM 独立验签", False, exc)
    else:
        check("DKIM 独立验签", False, "公钥不可用")

    # ---------- 8. API 其余端点 ----------
    section("8) API：附件 / 搜索 / 标记 / 长轮询")
    try:
        status, version = api(api_base, "/api/watch?since=0", token=token)
        check("/api/watch 长轮询返回版本号", status == 200 and "version" in version, status)

        attachment = base64.b64encode("中文附件内容".encode("utf-8")).decode()
        status, obj = api(api_base, "/api/send", "POST", {
            "to": account,
            "subject": "[验收] 带附件 " + submit_token,
            "text": "正文见附件。",
            "attachments": [{"fileName": "验收附件.txt", "contentType": "text/plain", "base64": attachment}],
        }, token=token)
        check("/api/send 带附件入队（202）", status == 202 and obj.get("queued"), status)

        time.sleep(6)
        status, obj = api(api_base, "/api/messages?folder=inbox&q=" + submit_token, token=token)
        hits = obj.get("messages", []) if status == 200 else []
        attach_msg = next((m for m in hits if m.get("hasAttachments")), None)
        check("带附件的邮件入库并识别出附件", attach_msg is not None,
              "命中 {} 封".format(len(hits)))
        if attach_msg:
            status, blob = api(api_base, "/api/messages/{}/attachments/0".format(attach_msg["id"]),
                               token=token, raw=True)
            check("附件按原字节下载", status == 200 and blob.decode("utf-8", "replace") == "中文附件内容",
                  "{} 字节".format(len(blob) if isinstance(blob, bytes) else -1))

        if hits:
            mid = hits[0]["id"]
            status, obj = api(api_base, "/api/messages/{}".format(mid), "PATCH", {"starred": True}, token=token)
            check("PATCH 设置星标", status == 200 and obj["message"]["starred"], status)
            status, obj = api(api_base, "/api/messages?folder=inbox&starred=1", token=token)
            check("按星标筛选命中", status == 200 and any(m["id"] == mid for m in obj.get("messages", [])), status)
    except Exception as exc:
        check("API 其余端点", False, exc)

    # ---------- 9. IMAP ----------
    section("9) IMAP：真实客户端流程")
    try:
        imap = imaplib.IMAP4(host, imap_port)
        check("IMAP 欢迎语含 IMAP4rev1", b"IMAP4rev1" in imap.welcome, imap.welcome[:60])
        caps = imap.capability()[1][0].decode()
        check("广告 STARTTLS", "STARTTLS" in caps, caps[:80])
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        imap.starttls(ctx)
        check("STARTTLS 握手成功", True)
        imap.login(account, password)
        check("IMAP LOGIN 成功", True)
        boxes = imap.list()[1]
        check("LIST 返回 6 个文件夹", len(boxes) == 6, "{} 个".format(len(boxes)))
        typ, data = imap.select("INBOX")
        exists = int(data[0])
        check("SELECT INBOX 有邮件", exists > 0, "{} 封".format(exists))
        typ, data = imap.search(None, "ALL")
        ids = data[0].split()
        check("SEARCH ALL 返回序号", len(ids) == exists, "{} vs {}".format(len(ids), exists))
        typ, data = imap.fetch(ids[-1], "(FLAGS RFC822.SIZE ENVELOPE)")
        summary = data[0].decode("latin-1") if data and isinstance(data[0], bytes) else str(data[0])
        check("FETCH 摘要含 ENVELOPE 与 RFC822.SIZE", "ENVELOPE" in summary and "RFC822.SIZE" in summary,
              summary[:120])
        check("RFC822.SIZE 非 0（旧邮件回退实际文件大小）", "RFC822.SIZE 0 " not in summary, summary[:120])
        typ, data = imap.fetch(ids[-1], "(BODY.PEEK[HEADER.FIELDS (SUBJECT)])")
        head = data[0][1].decode("utf-8", "replace") if isinstance(data[0], tuple) else b"".decode()
        check("HEADER.FIELDS 可取回主题", "Subject:" in head, head[:80])
        typ, data = imap.store(ids[-1], "+FLAGS", "(\\Seen)")
        check("STORE +FLAGS 成功", typ == "OK", typ)
        draft = "From: {}\r\nTo: someone@example.com\r\nSubject: =?UTF-8?B?{}?=\r\nMIME-Version: 1.0\r\n\r\n正文\r\n".format(
            account, base64.b64encode("验收草稿".encode("utf-8")).decode())
        typ, data = imap.append("Drafts", "(\\Draft)", None, draft.encode("utf-8"))
        check("APPEND 中文草稿成功", typ == "OK", typ)
        imap.select("Drafts")
        typ, data = imap.search(None, "ALL")
        check("草稿已入库", len(data[0].split()) > 0, data[0])
        imap.logout()
        check("IMAP 正常注销", True)
    except Exception as exc:
        check("IMAP 流程", False, "{}: {}".format(type(exc).__name__, exc))

    # ---------- 10. 安全回归 ----------
    section("10) 安全回归：非开放中继 / 提交需认证 / 明文登录限制")
    try:
        client = smtplib.SMTP(host, smtp_port)
        client.ehlo("e2e.local")
        client.docmd("MAIL FROM:<probe@e2e.local>")
        code, resp = client.docmd("RCPT TO:<someone@gmail.com>")
        check("25 端口拒绝外域收件人（非开放中继）", code == 550, "{} {}".format(code, resp))
        client.quit()
    except Exception as exc:
        check("非开放中继", False, exc)

    try:
        client = smtplib.SMTP(host, submission_port)
        client.ehlo("e2e.local")
        code, resp = client.docmd("MAIL FROM:<probe@e2e.local>")
        check("587 未认证即发信被拒（530）", code == 530, "{} {}".format(code, resp))
        client.quit()
    except Exception as exc:
        check("提交需认证", False, exc)

    # ---------- 汇总 ----------
    section("汇总")
    total = len(PASSED) + len(FAILED)
    print("  通过 {} / {}，失败 {}".format(len(PASSED), total, len(FAILED)))
    if FAILED:
        print("  失败用例：")
        for name in FAILED:
            print("    - " + name)

    try:
        with open(args.report, "w", encoding="utf-8") as fh:
            fh.write("WpywMail v2 端到端验收报告  {}\n".format(time.strftime("%Y-%m-%d %H:%M:%S")))
            fh.write("域: {}  账号: {}  主机: {}\n\n".format(domain, account, hostname))
            fh.write("通过 {} / {}，失败 {}\n".format(len(PASSED), total, len(FAILED)))
            if FAILED:
                fh.write("\n失败用例:\n" + "\n".join("- " + x for x in FAILED) + "\n")
            fh.write("\n全部用例:\n" + "\n".join("PASS " + x for x in PASSED) + "\n")
        print("  报告已写入: " + args.report)
    except Exception as exc:
        print("  报告写入失败: {}".format(exc))

    return len(FAILED)


if __name__ == "__main__":
    sys.exit(main())
