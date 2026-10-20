from sentinel.core.http import HttpClient
from sentinel.modules import ip as ip_mod


def test_private_ip_not_queried():
    rep = ip_mod.triage("192.168.1.1", HttpClient())
    assert any("私有" in f.value for f in rep.findings)
    assert not rep.sources  # 没有产生任何出网查询


def test_invalid_ip():
    rep = ip_mod.triage("999.999.999.999", HttpClient())
    assert any("不是合法" in f.value for f in rep.findings)
