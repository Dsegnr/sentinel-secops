from sentinel.core.assets import AssetStore, kind_to_type
from sentinel.core.findings import FindingStore


def test_asset_upsert_and_link(tmp_path):
    store = AssetStore(tmp_path)
    first = store.upsert("ip", "8.8.8.8", case="case-1")
    second = store.upsert("ip", "8.8.8.8", case="case-2")
    assert first["id"] == second["id"]
    assert "case-2" in second["cases"]
    assert kind_to_type("username") == "account"
    assert kind_to_type("user") == "account"
    assert kind_to_type("ip") == "ip"


def test_finding_lifecycle(tmp_path):
    store = FindingStore(tmp_path)
    finding = store.create("测试发现", severity="high", source="manual", asset="a-1")
    assert finding["status"] == "open"
    assert store.stats()["open"] == 1
    store.set_status(finding["id"], "closed", note="已处理")
    again = store.get(finding["id"])
    assert again["status"] == "closed"
    assert again["notes"] and again["notes"][0]["text"] == "已处理"
    assert store.stats()["open"] == 0
    store.add_note(finding["id"], "补充说明")
    assert len(store.get(finding["id"])["notes"]) == 2
