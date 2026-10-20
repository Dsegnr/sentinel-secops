from sentinel.core.case import filter_cases, grep_cases

ITEMS = [
    {"name": "20261011T205003-ip-8.8.8.8", "kind": "ip", "target": "8.8.8.8"},
    {"name": "20261011T205000-phone-+8613800138000", "kind": "phone", "target": "+8613800138000"},
    {"name": "20261011T205100-domain-example.com", "kind": "domain", "target": "example.com"},
]


def test_no_filter_returns_all():
    assert filter_cases(ITEMS) == ITEMS


def test_keyword_matches_name_and_target():
    assert [c["name"] for c in filter_cases(ITEMS, q="8.8.8.8")] == ["20261011T205003-ip-8.8.8.8"]
    assert len(filter_cases(ITEMS, q="EXAMPLE.COM")) == 1  # 大小写不敏感
    assert filter_cases(ITEMS, q="no-such") == []


def test_kind_filter():
    assert [c["kind"] for c in filter_cases(ITEMS, kind="phone")] == ["phone"]
    assert len(filter_cases(ITEMS, kind="IP")) == 1


def test_combined_filter():
    assert filter_cases(ITEMS, q="example", kind="domain")[0]["kind"] == "domain"
    assert filter_cases(ITEMS, q="8.8.8.8", kind="phone") == []


def test_grep_cases_finds_snippet(tmp_path):
    cases = tmp_path / "cases"
    hit_dir = cases / "c-hit"
    hit_dir.mkdir(parents=True)
    (hit_dir / "report.md").write_text("……威胁情报命中 203.0.113.9，建议阻断……", encoding="utf-8")
    clean_dir = cases / "c-clean"
    clean_dir.mkdir(parents=True)
    (clean_dir / "report.md").write_text("一切正常", encoding="utf-8")
    hits = grep_cases(cases, [{"name": "c-hit"}, {"name": "c-clean"}], "203.0.113.9")
    assert len(hits) == 1
    assert "203.0.113.9" in hits[0]["snippet"]


def test_grep_limits_and_edge_cases(tmp_path):
    cases = tmp_path / "cases"
    items = []
    for index in range(5):
        case = cases / f"c-{index}"
        case.mkdir(parents=True)
        (case / "report.md").write_text("keyword here", encoding="utf-8")
        items.append({"name": f"c-{index}"})
    assert len(grep_cases(cases, items, "keyword", limit=2)) == 2
    assert grep_cases(cases, [{"name": "missing"}], "keyword") == []
    assert grep_cases(cases, items, "   ") == []
