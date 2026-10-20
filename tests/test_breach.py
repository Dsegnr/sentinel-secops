from sentinel.core import netintel
from sentinel.core.http import HttpClient
from sentinel.modules import breach


def test_breach_masked(monkeypatch):
    monkeypatch.setattr(netintel, "pwned_password_count", lambda password, client: 1234)
    rep = breach.triage("hunter2secret", HttpClient())
    text = rep.to_json()
    assert "hunter2secret" not in text
    assert "SHA-1 前缀" in rep.target
    values = {f.key: f.value for f in rep.findings}
    assert values["命中次数"] == "1234 次"
    assert "高" in values["风险等级"]


def test_breach_zero(monkeypatch):
    monkeypatch.setattr(netintel, "pwned_password_count", lambda password, client: 0)
    rep = breach.triage("Zq9!vX2#kLm8", HttpClient())
    values = {f.key: f.value for f in rep.findings}
    assert values["命中次数"] == "0 次"
    assert values["风险等级"].startswith("低")
