from sentinel.core import notify as notify_mod


def test_severity_helpers(monkeypatch):
    monkeypatch.setattr(notify_mod, "load_config", lambda: {"monitor": {"notify_min_severity": "medium"}})
    assert notify_mod.notify_min_severity() == "medium"
    assert notify_mod.severity_at_least("high", "medium")
    assert not notify_mod.severity_at_least("low", "medium")


def test_notify_finding_respects_threshold(monkeypatch):
    monkeypatch.setattr(notify_mod, "load_config", lambda: {"monitor": {"notify_min_severity": "high"}})
    sent: list[str] = []
    monkeypatch.setattr(notify_mod, "notify", lambda text, payload=None: (sent.append(text), True)[1])
    assert notify_mod.notify_finding({"title": "高危", "severity": "critical"}) is True
    assert notify_mod.notify_finding({"title": "低危", "severity": "low"}) is False
    assert len(sent) == 1 and "critical" in sent[0]


def test_notify_without_webhook(monkeypatch):
    monkeypatch.setattr(notify_mod, "load_config", lambda: {"monitor": {"webhook_url": ""}})
    assert notify_mod.notify("hello") is False


def test_notify_summary_lines(monkeypatch):
    captured: dict = {}

    def fake_notify(text, payload=None):
        captured["text"] = text
        return True

    monkeypatch.setattr(notify_mod, "notify", fake_notify)
    assert notify_mod.notify_summary("标题", ["a", "  ", "b"]) is True
    assert "标题" in captured["text"]
    assert "· a" in captured["text"] and "· b" in captured["text"]
