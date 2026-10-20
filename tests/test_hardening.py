from sentinel.core.hardening import available_actions, build_script, netbios_targets

DIRTY = {
    "rdp": ["enabled"],
    "smb1": ["enabled"],
    "llmnr": ["policy=unset(default-on)"],
    "netbios": [
        "Intel(R) Wi-Fi 6E AX211 160MHz|TcpipNetbiosOptions=0",
        "Famatech Radmin VPN Ethernet Adapter|TcpipNetbiosOptions=2",
    ],
}

CLEAN = {
    "rdp": ["disabled"],
    "smb1": ["disabled"],
    "llmnr": ["policyEnableMulticast=0"],
    "netbios": ["Wi-Fi|TcpipNetbiosOptions=2"],
}


def test_available_actions_flags():
    actions = {a["key"]: a for a in available_actions(DIRTY)}
    assert all(actions[k]["active"] for k in ("llmnr", "netbios", "rdp", "smb1"))
    assert "1 个" in actions["netbios"]["detail"]  # 只有一个网卡是 =0


def test_available_actions_clean():
    actions = {a["key"]: a for a in available_actions(CLEAN)}
    assert not any(a["active"] for a in actions.values())


def test_netbios_targets_only_default_on():
    assert netbios_targets(DIRTY) == ["Intel(R) Wi-Fi 6E AX211 160MHz"]


def test_build_script_dirty_baseline():
    script = build_script(DIRTY, baseline_name="baseline-x.json", baseline_sha="abc123")
    assert "param(" in script and "$Apply" in script and "$Undo" in script
    assert "EnableMulticast" in script
    assert "Intel(R) Wi-Fi 6E AX211 160MHz" in script
    assert "Radmin" not in script  # 已达标网卡不固化
    assert "fDenyTSConnections" in script
    assert "EnableSMB1Protocol" in script
    assert "abc123" in script and "baseline-x.json" in script
    assert "预览" in script


def test_build_script_clean_baseline():
    script = build_script(CLEAN, baseline_name="b.json", baseline_sha="x")
    assert "没有需要处理的加固项" in script
    assert "EnableMulticast" not in script
    assert "fDenyTSConnections" not in script


def test_quotes_escaped():
    data = {
        "rdp": ["disabled"],
        "smb1": ["disabled"],
        "llmnr": ["policy=unset"],
        "netbios": ["Bob's NIC|TcpipNetbiosOptions=0"],
    }
    script = build_script(data, baseline_name="b", baseline_sha="s")
    assert "Bob''s NIC" in script
