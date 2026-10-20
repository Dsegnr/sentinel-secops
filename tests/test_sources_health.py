from sentinel.core.sources_health import probe_http, probe_tcp, run_checks


class FakeResp:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text

    def iter_content(self, n):
        yield self.text.encode()


class FakeSession:
    def __init__(self, resp):
        self.resp = resp

    def get(self, url, **kwargs):
        return self.resp


def test_probe_http_ok():
    row = probe_http({"name": "X", "kind": "http", "url": "https://x.example/"}, FakeSession(FakeResp()))
    assert row["ok"] and row["status"] == 200 and "ok" in row["sample"]


def test_probe_http_fail():
    class Boom:
        def get(self, url, **kwargs):
            raise RuntimeError("down")

    row = probe_http({"name": "X", "kind": "http", "url": "https://x/"}, Boom())
    assert not row["ok"] and "down" in row["error"]


def test_probe_http_stream():
    row = probe_http(
        {"name": "S", "kind": "http", "url": "https://x/", "stream": True},
        FakeSession(FakeResp(text="# header line")),
    )
    assert row["ok"] and "# header" in row["sample"]


def test_probe_tcp_down():
    row = probe_tcp({"name": "T", "kind": "tcp", "host": "127.0.0.1", "port": 1, "query": "x", "timeout": 1})
    assert not row["ok"]


def test_run_checks_summary():
    probes = [
        {"name": "A", "kind": "http", "url": "https://a/"},
        {"name": "B", "kind": "http", "url": "https://b/"},
    ]
    data = run_checks(session=FakeSession(FakeResp()), probes=probes)
    assert data["total"] == 2 and data["ok"] == 2
    assert [r["name"] for r in data["results"]] == ["A", "B"]
