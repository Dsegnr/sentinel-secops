import json

from sentinel.core.posture import baseline_issues, diff_baselines


def test_issues_empty_when_clean():
    data = {
        "rdp": ["disabled"],
        "smb1": ["disabled"],
        "firewall": ["Domain|enabled=True|inbound=Block"],
        "llmnr": ["policyEnableMulticast=0"],
        "netbios": ["Wi-Fi|TcpipNetbiosOptions=2"],
        "hostsOther": [],
    }
    assert baseline_issues(data) == []


def test_issues_detect_problems():
    data = {
        "rdp": ["enabled"],
        "smb1": ["enabled"],
        "firewall": ["Public|enabled=False|inbound=Allow"],
        "llmnr": ["policy=unset(default-on)"],
        "netbios": ["Wi-Fi|TcpipNetbiosOptions=0", "Eth|TcpipNetbiosOptions=2"],
        "hostsOther": ["172.33.180.152 host.docker.internal"],
    }
    issues = baseline_issues(data)
    joined = "；".join(issues)
    for keyword in ("RDP", "SMBv1", "防火墙", "LLMNR", "NetBIOS", "hosts"):
        assert keyword in joined
    assert len(issues) == 6


def test_issues_missing_keys():
    assert baseline_issues({}) == []


def test_diff_baselines():
    old = {"hosts": ["a"], "rdp": ["disabled"], "ports": ["3389|svc"]}
    new = {"hosts": ["a", "b"], "rdp": ["enabled"], "ports": ["3389|svc"]}
    diff = diff_baselines(old, new)
    assert diff["hosts"]["added"] == ["b"] and diff["hosts"]["removed"] == []
    assert diff["rdp"]["added"] == ["enabled"] and diff["rdp"]["removed"] == ["disabled"]
    assert "ports" not in diff
    assert diff_baselines({}, {}) == {}


def test_baseline_diff_new_keys(tmp_path):
    from sentinel.core.tasks import TaskManager

    manager = TaskManager(tmp_path)
    prev = tmp_path / "checks/out/baseline-1.json"
    latest = tmp_path / "checks/out/baseline-2.json"
    prev.parent.mkdir(parents=True, exist_ok=True)
    prev.write_text(
        json.dumps({"capturedAt": "t1", "hosts": ["a"], "rdp": ["disabled"], "autoruns": ["x"]}),
        encoding="utf-8",
    )
    latest.write_text(
        json.dumps({"capturedAt": "t2", "hosts": ["a"], "rdp": ["enabled"], "autoruns": ["x", "y"]}),
        encoding="utf-8",
    )
    diff = manager._baseline_diff(prev, latest)
    assert "rdp" in diff and "autoruns" in diff
    assert diff["rdp"]["added"] == ["enabled"] and diff["rdp"]["removed"] == ["disabled"]
    assert diff["autoruns"]["added"] == ["y"]


def test_patrol_refreshes_stale_blocklist(tmp_path, monkeypatch):
    from sentinel.core import tasks as tasks_mod

    manager = tasks_mod.TaskManager(tmp_path)
    calls = {"update": 0}

    class StaleStore:
        def __init__(self, data_dir):
            pass

        def age_hours(self):
            return 99.0

        def update(self, client):
            calls["update"] += 1
            return {"firehol_level1": {"ok": True, "count": 5}}

    monkeypatch.setattr(tasks_mod, "BlocklistStore", StaleStore)
    task = tasks_mod.Task(id="t1", kind="patrol", title="x")
    manager._maybe_refresh_blocklist(task)
    assert calls["update"] == 1
    assert any("封堵清单更新" in line for line in task.log)


def test_patrol_skips_fresh_blocklist(tmp_path, monkeypatch):
    from sentinel.core import tasks as tasks_mod

    manager = tasks_mod.TaskManager(tmp_path)

    class FreshStore:
        def __init__(self, data_dir):
            pass

        def age_hours(self):
            return 1.0

    monkeypatch.setattr(tasks_mod, "BlocklistStore", FreshStore)
    task = tasks_mod.Task(id="t2", kind="patrol", title="x")
    manager._maybe_refresh_blocklist(task)
    assert any("跳过" in line for line in task.log)
