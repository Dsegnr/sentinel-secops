from sentinel.core.models import TriageReport
from sentinel.modules import domain


def test_normalize_domain():
    assert domain.normalize_domain("HTTPS://Example.COM/path?q=1") == "example.com"
    assert domain.normalize_domain("user@mail.example.com:443") == "mail.example.com"
    assert domain.normalize_domain("例子.中国").startswith("xn--")
    assert domain.normalize_domain("") == ""


def test_assess_rating_a():
    rep = TriageReport(kind="domain", target="x.com")
    rep.add("SPF", "v=spf1 -all｜判定：硬失败（-all，配置严格）")
    rep.add("DMARC", "p=reject｜判定：拒收（严格）")
    rep.add("安全响应头", "已配置 6/6；齐全")
    domain._assess(rep)
    values = {f.key: f.value for f in rep.findings}
    assert values["体检评级"].startswith("A")
    assert "问题清单" not in values


def test_assess_rating_warns():
    rep = TriageReport(kind="domain", target="x.com")
    rep.add("SPF", "未配置（任何人可伪造该域发信）")
    rep.add("DMARC", "未配置（建议：v=DMARC1; p=none 起步）")
    rep.add("安全响应头", "已配置 3/6；缺失：HSTS、CSP、X-Frame-Options")
    rep.add("证书到期", "Dec 25 22:56:35 2026 GMT（剩余 5 天）")
    domain._assess(rep)
    values = {f.key: f.value for f in rep.findings}
    assert values["体检评级"][0] in ("C", "D")
    assert "SPF 未配置" in values["问题清单"]
    assert "证书 5 天内到期" in values["问题清单"]
