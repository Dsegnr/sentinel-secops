import json
from datetime import datetime, timedelta

from sentinel.core.blocklist import BlocklistStore, parse_cidrs, should_refresh


def test_parse_cidrs():
    text = "# comment\n1.2.3.0/24\nbad-line\n1.2.3.0/24\n10.0.0.0/8 ; note\n; another\n"
    assert parse_cidrs(text) == ["1.2.3.0/24", "10.0.0.0/8"]


def test_store_check_and_export(tmp_path):
    store = BlocklistStore(tmp_path)
    (store.dir / "firehol_level1.netset").write_text("203.0.113.0/24\n2001:db8::/32\n", encoding="utf-8")
    assert [str(n) for n, _ in store.load_ranges()] == ["203.0.113.0/24", "2001:db8::/32"]
    hits = store.check_ip("203.0.113.7")
    assert hits and hits[0]["cidr"] == "203.0.113.0/24"
    assert store.check_ip("198.51.100.1") == []
    script = store.export_firewall_script()
    assert "New-NetFirewallRule" in script
    assert "203.0.113.0/24" in script
    assert "Sentinel-Blocklist" in script
    csv = store.export_csv()
    assert "firehol_level1,203.0.113.0/24" in csv


def test_check_invalid_ip(tmp_path):
    store = BlocklistStore(tmp_path)
    try:
        store.check_ip("not-an-ip")
        raise AssertionError("应当抛出 ValueError")
    except ValueError:
        pass


def test_custom_entries_lifecycle(tmp_path):
    store = BlocklistStore(tmp_path)
    ok, _ = store.add_custom("203.0.113.9")
    assert ok and store.custom_list() == ["203.0.113.9/32"]  # 统一归一化为 CIDR
    again, message = store.add_custom("203.0.113.9")
    assert not again and "已存在" in message
    bad, _ = store.add_custom("not-an-ip")
    assert not bad
    hits = store.check_ip("203.0.113.9")
    assert hits and hits[0]["source"] == "自定义封堵"
    script = store.export_firewall_script()
    assert "203.0.113.9" in script
    assert store.remove_custom("203.0.113.9")
    assert store.custom_list() == []
    assert store.check_ip("203.0.113.9") == []


def test_age_hours_none_when_empty(tmp_path):
    store = BlocklistStore(tmp_path)
    assert store.age_hours() is None


def test_age_hours_from_meta(tmp_path):
    store = BlocklistStore(tmp_path)
    old = (datetime.now() - timedelta(hours=30)).isoformat(timespec="seconds")
    store.meta_path.write_text(
        json.dumps({"sources": {"firehol_level1": {"updated": old, "count": 1}}}),
        encoding="utf-8",
    )
    age = store.age_hours()
    assert age is not None and 29 < age < 31


def test_should_refresh():
    assert should_refresh(None, 24) is True
    assert should_refresh(1.0, 24) is False
    assert should_refresh(25.0, 24) is True
