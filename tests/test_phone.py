from sentinel.modules import phone


def test_parse_cn_mobile():
    rep = phone.triage("+8613800138000")
    values = {f.key: f.value for f in rep.findings}
    assert values["E.164"] == "+8613800138000"
    assert values["国家/地区"] == "CN"
    assert values["合法性"] == "有效号码"


def test_parse_local_with_region():
    rep = phone.triage("13800138000", region="CN")
    values = {f.key: f.value for f in rep.findings}
    assert values["E.164"] == "+8613800138000"


def test_parse_garbage():
    rep = phone.triage("not-a-number")
    assert any(f.confidence.value == "unavailable" for f in rep.findings)
