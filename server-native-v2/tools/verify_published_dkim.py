# -*- coding: utf-8 -*-
"""
用「DNS 上已发布的 DKIM 公钥」独立验证真实投递报文的签名。

与 e2e_acceptance.py 内的验签不同：本脚本**不接触私钥**，只吃 DNS TXT 记录的
字面值（v=DKIM1; k=rsa; p=...），因此它证明的是收件方（Gmail/Outlook/QQ）
将会看到的事实：公钥一发布，签名即可被验证通过。

零第三方依赖：手写 DER 解析 SPKI -> (n, e)，再用 pow() 做 RSA-SHA256
PKCS#1 v1.5 验签。Python 3.8+ 可跑。

用法:
  python verify_published_dkim.py --dns-file dns-dkim-published.txt --eml a.eml --eml b.eml
  python verify_published_dkim.py --dns-file dns-dkim-published.txt --eml-dir C:\\path\\raw
  python verify_published_dkim.py --dns-file ... --eml-dir ... --selector mail --domain wpy.email

--dns-file 内容可以是整条 TXT（v=DKIM1; k=rsa; p=...），也可以是只含 p= 后面
那段 base64 的纯文本；还能容忍 DNS 分段留下的空白/换行。

退出码 = 验签失败的报文数（0 表示全部通过）。
"""
from __future__ import print_function

import argparse
import base64
import hashlib
import os
import re
import sys

SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


# ------------------------------------------------------------------ DER / RSA

def der_read(data, offset):
    """读一个 TLV，返回 (tag, content, next_offset)。仅支持短/长形式长度。"""
    tag = data[offset]
    length = data[offset + 1]
    offset += 2
    if length & 0x80:
        count = length & 0x7F
        length = int.from_bytes(data[offset:offset + count], "big")
        offset += count
    return tag, data[offset:offset + length], offset + length


def spki_to_rsa(der):
    """从 SubjectPublicKeyInfo 里取出 (n, e)。"""
    _, spki, _ = der_read(der, 0)
    _, _, off = der_read(spki, 0)                 # AlgorithmIdentifier，跳过
    _, bitstring, _ = der_read(spki, off)         # subjectPublicKey BIT STRING
    if bitstring[0] != 0:
        raise ValueError("BIT STRING 未使用位不为 0")
    _, rsa_seq, _ = der_read(bitstring[1:], 0)
    _, modulus, off2 = der_read(rsa_seq, 0)
    _, exponent, _ = der_read(rsa_seq, off2)
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def rsa_verify_sha256(n, e, signature, message):
    try:
        size = (n.bit_length() + 7) // 8
        if len(signature) != size:
            return False, "签名长度 %d 与模长 %d 不符" % (len(signature), size)
        m = pow(int.from_bytes(signature, "big"), e, n)
        em = m.to_bytes(size, "big")
        if em[0] != 0x00 or em[1] != 0x01:
            return False, "PKCS#1 v1.5 padding 前缀不符"
        sep = em.index(b"\x00", 2)
        digest_info = em[sep + 1:]
        expected = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
        if digest_info != expected:
            return False, "DigestInfo 不匹配（摘要或签名输入被改动）"
        return True, ""
    except Exception as exc:                       # noqa: BLE001 - 验签失败即失败
        return False, "%s: %s" % (type(exc).__name__, exc)


# ------------------------------------------------------------------ DNS TXT 解析

def parse_txt_record(text):
    """从 TXT 字面值里取出 p= 的 base64 并解析成 (n, e)。"""
    flat = re.sub(r"\s+", "", text)                # DNS 分段/换行一律去掉
    m = re.search(r"p=([A-Za-z0-9+/=]+)", flat)
    if not m:
        raise ValueError("TXT 里找不到 p= 公钥段")
    pem_b64 = m.group(1)
    try:
        der = base64.b64decode(pem_b64, validate=True)
    except Exception as exc:                       # noqa: BLE001
        raise ValueError("p= 不是合法 base64: %s" % exc)
    return spki_to_rsa(der), pem_b64


def record_tags(text):
    flat = re.sub(r"\s+", " ", text).strip()
    tags = {}
    for part in flat.split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


# ------------------------------------------------------------------ DKIM 验证

def split_message(raw):
    sep = raw.find(b"\r\n\r\n")
    if sep < 0:
        return [], raw
    head, body = raw[:sep], raw[sep + 4:]
    headers, name = [], None
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
    lines = [re.sub(r"[ \t]+", " ", ln).rstrip(" \t") for ln in text.split("\n")]
    joined = "\r\n".join(lines).rstrip("\r\n")
    return (joined + "\r\n").encode("latin-1") if joined else b""


def verify(raw, n, e):
    """返回 (是否通过, 说明, 详情 dict)。relaxed/relaxed + rsa-sha256。"""
    headers, body = split_message(raw)
    sigs = [v for k, v in headers if k.lower() == "dkim-signature"]
    if not sigs:
        return False, "报文里没有 DKIM-Signature 头", {}
    tags = {}
    for part in sigs[0].split(";"):
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    info = {"d": tags.get("d"), "s": tags.get("s"), "a": tags.get("a"),
            "c": tags.get("c"), "h": tags.get("h"), "bh": tags.get("bh"),
            "b_len": len(tags.get("b", ""))}

    if tags.get("a") != "rsa-sha256":
        return False, "非 rsa-sha256（%s）" % tags.get("a"), info
    if tags.get("c", "simple/simple") != "relaxed/relaxed":
        return False, "非 relaxed/relaxed（%s）" % tags.get("c"), info

    bh_calc = base64.b64encode(hashlib.sha256(canon_body(body)).digest()).decode()
    info["bh_calc"] = bh_calc
    if bh_calc != tags.get("bh"):
        return False, "正文哈希 bh 不匹配（正文被改动）", info

    signing = ""
    for name in tags.get("h", "").split(":"):
        if not name.strip():
            continue
        hit = next((v for k, v in headers if k.lower() == name.strip().lower()), None)
        if hit is None:
            return False, "被签名的头缺失: %s" % name, info
        # RFC 6376 §3.7 第 2 步之 1：每个被签名头后面必须跟一个 CRLF
        signing += canon_header(name, hit) + "\r\n"
    # 之 2：DKIM-Signature 头本身放在**最后**，且结尾**不带 CRLF**
    signing += canon_header("DKIM-Signature", sigs[0].replace(tags["b"], "").rstrip())

    ok, why = rsa_verify_sha256(n, e, base64.b64decode(tags["b"]), signing.encode("ascii"))
    return ok, why, info


# ------------------------------------------------------------------ 主流程

def collect(paths, eml_dir):
    files = list(paths)
    if eml_dir:
        for name in sorted(os.listdir(eml_dir)):
            if name.lower().endswith(".eml"):
                files.append(os.path.join(eml_dir, name))
    return files


def main():
    ap = argparse.ArgumentParser(description="用 DNS 已发布的公钥验证 DKIM")
    ap.add_argument("--dns-file", required=True, help="含已发布 TXT 值的文本文件")
    ap.add_argument("--eml", action="append", default=[], help="待验报文（可重复）")
    ap.add_argument("--eml-dir", help="目录下所有 .eml 都验")
    ap.add_argument("--selector", default=None, help="期望的选择器（校验 s=）")
    ap.add_argument("--domain", default=None, help="期望的签名域（校验 d=）")
    args = ap.parse_args()

    raw_txt = open(args.dns_file, "rb").read().decode("utf-8", "replace")
    try:
        (n, e), pem_b64 = parse_txt_record(raw_txt)
    except ValueError as exc:
        print("[致命] 无法从 DNS 值解析公钥: %s" % exc)
        return 2
    tags = record_tags(raw_txt)

    print("=" * 68)
    print("DNS 已发布 DKIM 公钥")
    print("=" * 68)
    print("  记录长度   : %d 字符" % len(re.sub(r"\s+", "", raw_txt)))
    print("  v / k      : %s / %s" % (tags.get("v"), tags.get("k")))
    print("  公钥位长   : %d bit" % n.bit_length())
    print("  公钥指数   : %d" % e)
    print("  p= 长度    : %d 字符 base64" % len(pem_b64))
    if tags.get("v") != "DKIM1":
        print("  [警告] v 不是 DKIM1")
    if n.bit_length() < 1024:
        print("  [警告] 密钥短于 1024 bit，多数收件方会直接判失败")

    files = collect(args.eml, args.eml_dir)
    if not files:
        print("\n[致命] 没有指定任何 .eml")
        return 2

    print("\n" + "=" * 68)
    print("对真实报文验签（只用上面这把公钥，不接触私钥）")
    print("=" * 68)
    failures = 0
    for path in files:
        name = os.path.basename(path)
        data = open(path, "rb").read()
        ok, why, info = verify(data, n, e)
        print("\n%s  (%d 字节)" % (name, len(data)))
        print("  d=%s s=%s a=%s c=%s" % (info.get("d"), info.get("s"), info.get("a"), info.get("c")))
        print("  签名字段 b 长度 %s，h=%s" % (info.get("b_len"), info.get("h")))
        print("  正文哈希 bh: %s" % ("一致" if info.get("bh") == info.get("bh_calc") else "不一致"))
        if args.domain and info.get("d") != args.domain:
            ok, why = False, "d= 与期望域名 %s 不符（实际 %s）" % (args.domain, info.get("d"))
        if args.selector and info.get("s") != args.selector:
            ok, why = False, "s= 与期望选择器 %s 不符（实际 %s）" % (args.selector, info.get("s"))
        if ok:
            print("  [通过] RSA-SHA256 签名验证成功 —— 收件方用这条 DNS 记录即可验签")
        else:
            print("  [失败] %s" % why)
            failures += 1

    print("\n" + "=" * 68)
    print("合计: %d 个报文，通过 %d，失败 %d" % (len(files), len(files) - failures, failures))
    print("=" * 68)
    return failures


if __name__ == "__main__":
    sys.exit(main())
