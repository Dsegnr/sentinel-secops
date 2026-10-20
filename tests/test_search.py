from sentinel.core.search import build_search_links


def test_search_links_encoding():
    links = build_search_links("username", "堃")
    assert len(links) >= 8
    baidu = next(l for l in links if l["name"] == "百度")
    assert "%E5%A0%83" in baidu["url"]


def test_search_links_phone_extras():
    links = build_search_links("phone", "+8613800138000")
    names = [l["name"] for l in links]
    assert any("12321" in n for n in names)
    assert build_search_links("username", "   ") == []
