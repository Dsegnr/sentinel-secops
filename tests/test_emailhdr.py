from sentinel.core import netintel
from sentinel.core.http import HttpClient
from sentinel.modules import emailhdr

SAMPLE = (
    'From: "AliPay" <security@alipay-bad.example>\n'
    "Return-Path: <attacker@evil.tk>\n"
    "Reply-To: <reply@evil.tk>\n"
    "Subject: 账户异常\n"
    "Received: from mail.evil.tk by mx.local;\n"
    "Received: from out by mail.evil.tk;\n"
    "Authentication-Results: mx.local; spf=fail dkim=none dmarc=fail\n"
    "Message-ID: <abc@evil.tk>\n"
    "\n"
    "https://taobao.com.secure-login.tk/account/login.exe\n"
)


def test_email_analysis(monkeypatch):
    monkeypatch.setattr(netintel, "resolve_records", lambda *args, **kwargs: {"TXT": []})
    rep = emailhdr.triage(SAMPLE, HttpClient())
    values = {f.key: f.value for f in rep.findings}
    assert "SPF=fail" in values["认证结果（由收件方代写）"]
    combined = "；".join(values.values())
    assert "不一致" in combined
    assert "可疑链接" in combined
    assert any("认证结果的权威判定" in n for n in rep.notes)


def test_headers_folding():
    fields = emailhdr._parse_headers("Subject: hello\n world\nX-A: 1\n")
    assert fields["subject"] == ["hello world"]
    assert fields["x-a"] == ["1"]
