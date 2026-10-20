from sentinel.modules import username as u


class FakeResp:
    def __init__(self, status=200, text=""):
        self.status_code = status
        self.text = text
        self.content = text.encode()


class FakeClient:
    timeout = 8

    def __init__(self, resp):
        self.resp = resp

    def get(self, url, **kwargs):
        return self.resp


def test_marker_semantics():
    platform = {
        "name": "T",
        "url": "https://t.example/{u}",
        "present_markers": ['"ok":true'],
        "missing_markers": ['"gone"'],
        "ok_status": [200],
        "missing_status": [404],
    }
    assert u.check_platform(platform, "a", FakeClient(FakeResp(200, '{"ok":true}')))["state"] == "exists"
    assert u.check_platform(platform, "a", FakeClient(FakeResp(200, '{"gone":1}')))["state"] == "missing"
    assert u.check_platform(platform, "a", FakeClient(FakeResp(200, "neither")))["state"] == "unknown"
    assert u.check_platform(platform, "a", FakeClient(FakeResp(404, "")))["state"] == "missing"


def test_status_only_site():
    platform = {"name": "S", "url": "https://s.example/{u}", "ok_status": [200], "missing_status": [404]}
    assert u.check_platform(platform, "a", FakeClient(FakeResp(200, "hi")))["state"] == "exists"
    assert u.check_platform(platform, "a", FakeClient(FakeResp(404, "")))["state"] == "missing"


def test_qq_avatar_paths():
    platform = {"name": "QQ", "url": "https://q.example/{u}", "check": "qq_avatar"}
    assert u.check_platform(platform, "abc", FakeClient(FakeResp(200, "x")))["state"] == "unknown"
    assert u.check_platform(platform, "10001", FakeClient(FakeResp(200, "x")))["state"] == "exists"
    resp404 = u.check_platform(platform, "10001", FakeClient(FakeResp(404, "")))
    assert resp404["state"] == "unknown"
