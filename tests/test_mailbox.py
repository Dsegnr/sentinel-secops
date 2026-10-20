from sentinel.core.http import HttpClient
from sentinel.core.models import TriageReport
from sentinel.modules import mailbox


def test_normalize_email():
    assert mailbox.normalize_email("  <Name.Tag+1@163.COM>  ") == "name.tag+1@163.com"
    assert mailbox.normalize_email("a@b.example.") == "a@b.example"
    assert mailbox.normalize_email("") == ""


def test_email_validation():
    assert mailbox.is_valid_email("a@b.com")
    assert mailbox.is_valid_email("x.y+z@sub.example.co")
    assert not mailbox.is_valid_email("a@b")
    assert not mailbox.is_valid_email("a b@c.com")
    assert not mailbox.is_valid_email("")


def test_provider_classification():
    p163 = mailbox.classify_provider("163.com")
    assert p163["kind"] == "free" and "网易" in p163["name"] and "abuse@163.com" in p163["channel"]
    assert mailbox.classify_provider("qq.com")["kind"] == "free"
    assert mailbox.classify_provider("mailinator.com")["kind"] == "disposable"
    assert mailbox.classify_provider("mail.mailinator.com")["kind"] == "disposable"
    assert mailbox.classify_provider("example.com")["kind"] == "corporate"


def test_gravatar_digest_lowercases():
    assert mailbox.gravatar_digest("ABC@Example.COM") == mailbox.gravatar_digest("abc@example.com")
    assert len(mailbox.gravatar_digest("a@b.co")) == 32


def test_triage_invalid_email_early_return():
    rep = mailbox.triage("not an email", HttpClient(retries=0))
    assert rep.kind == "mailbox"
    assert rep.has_key("格式校验")
    assert not rep.has_key("服务商")


def test_assess_disposable_and_no_mx():
    rep = TriageReport(kind="mailbox", target="x@mailinator.com")
    rep.add("服务商", "一次性 / 临时邮箱服务")
    rep.add("邮箱性质", "一次性邮箱（临时邮箱服务）")
    rep.add("MX 记录", "未配置 MX（该域当前无法收信）")
    mailbox._assess(rep)
    values = {f.key: f.value for f in rep.findings}
    assert "邮箱画像" in values
    assert "一次性" in values["风险与建议"]
    assert "不接收邮件" in values["风险与建议"]


def test_assess_corporate_spf_missing_and_gravatar():
    rep = TriageReport(kind="mailbox", target="x@corp.example")
    rep.add("服务商", "独立域邮箱（组织自建 / 企业邮箱）")
    rep.add("邮箱性质", "独立域邮箱（机构 / 企业域）")
    rep.add("MX 记录", "mail.corp.example")
    rep.add("SPF", "未配置（任何人可伪造该域发信）")
    rep.add("Gravatar 公开头像", "存在（公开头像：https://www.gravatar.com/avatar/abc）")
    mailbox._assess(rep)
    values = {f.key: f.value for f in rep.findings}
    assert "伪造" in values["风险与建议"]
    assert "Gravatar" in values["风险与建议"]
