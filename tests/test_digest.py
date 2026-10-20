import json

from sentinel.core.digest import build_digest, render_text
from sentinel.core.findings import FindingStore

_BASELINE = {
    "capturedAt": "2026-10-11T22:00:00",
    "hosts": [],
    "hostsOther": [],
    "certs": [],
    "ports": [],
    "tasks": [],
    "av": [],
    "autoruns": [],
    "rdp": ["disabled"],
    "smb1": ["disabled"],
    "firewall": ["Domain|enabled=True|inbound=Block"],
    "proxy": ["enable=0|server="],
    "admins": ["PC\\User"],
    "llmnr": ["policyEnableMulticast=0"],
    "netbios": ["Wi-Fi|TcpipNetbiosOptions=2"],
}


def _fixture(root):
    case = root / "cases" / "20261011T220000-ip-8.8.8.8"
    case.mkdir(parents=True)
    (case / "report.json").write_text(json.dumps({"kind": "ip", "target": "8.8.8.8"}), encoding="utf-8")
    (root / "data").mkdir()
    FindingStore(root / "data").create("高危测试发现", severity="high", source="test")
    out = root / "checks" / "out"
    out.mkdir(parents=True)
    (out / "baseline-20261011-220000.json").write_text(json.dumps(_BASELINE), encoding="utf-8")
    (out / "sources-health.json").write_text(
        json.dumps({"when": "2026-10-11T22:00:00", "ok": 16, "total": 17}), encoding="utf-8"
    )


def test_build_digest(tmp_path):
    _fixture(tmp_path)
    digest = build_digest(tmp_path)
    assert digest["cases"]["recent"] == 1
    assert digest["cases"]["kinds"] == {"ip": 1}
    assert digest["findings"]["open"] == 1
    assert digest["findings"]["by_severity"].get("high") == 1
    assert digest["findings"]["new"] == 1
    assert digest["findings"]["top"][0]["severity"] == "high"
    assert digest["baseline"]["issues"] == []
    assert digest["health"] == {"when": "2026-10-11T22:00:00", "ok": 16, "total": 17}
    assert digest["blocklist"]["age_hours"] is None


def test_render_text(tmp_path):
    _fixture(tmp_path)
    text = render_text(build_digest(tmp_path))
    assert "每日摘要" in text
    assert "待处理 1" in text
    assert "尚未同步" in text
    assert "16/17" in text
    assert "尚未体检" not in text
