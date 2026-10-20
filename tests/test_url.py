from sentinel.modules import url as url_mod


def test_brand_subdomain_and_tld():
    info = url_mod.analyze_structure("http://taobao.com.secure-login.tk/login.exe")
    issues = "；".join(info["issues"])
    assert "可疑顶级域" in issues
    assert "品牌" in issues
    assert "可执行" in issues


def test_ip_host_and_userinfo():
    info = url_mod.analyze_structure("http://admin@192.168.1.10:8080/x")
    issues = "；".join(info["issues"])
    assert "IP 地址" in issues
    assert "非标准端口" in issues
    assert "@" in issues


def test_punycode():
    info = url_mod.analyze_structure("https://xn--80ak6aa92e.com/")
    assert any("punycode" in i for i in info["issues"])


def test_offline_flags_safe_url():
    assert url_mod.offline_flags("https://www.example.com/a?b=1") == []


def test_scheme_default():
    info = url_mod.analyze_structure("example.com/login")
    assert info["url"].startswith("http://")
    assert info["host"] == "example.com"
