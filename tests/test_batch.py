from sentinel.core.batch import MAX_TARGETS, assess_report, parse_targets


def test_parse_targets():
    text = "# 注释\n8.8.8.8\n\n1.1.1.1\n8.8.8.8\n  example.com  \n"
    assert parse_targets(text) == ["8.8.8.8", "1.1.1.1", "example.com"]


def test_parse_targets_limit():
    text = "\n".join(f"10.0.0.{i}" for i in range(300))
    assert len(parse_targets(text)) == MAX_TARGETS


def _data(pairs: dict) -> dict:
    return {"findings": [{"key": k, "value": v} for k, v in pairs.items()]}


def test_assess_ip_blocklist_hit():
    risks = assess_report("ip", _data({"封堵清单命中": "FireHOL level1 203.0.113.0/24"}))
    assert risks and risks[0]["severity"] == "high"


def test_assess_ip_clean():
    risks = assess_report(
        "ip",
        _data({
            "封堵清单命中": "未命中 FireHOL/Spamhaus 清单",
            "blocklist.de 举报/攻击": "reports=0 / attacks=0",
        }),
    )
    assert risks == []


def test_assess_ip_attacks():
    risks = assess_report("ip", _data({"DShield 攻击记录": "attacks=5 / count=9"}))
    assert any(r["severity"] == "medium" for r in risks)


def test_assess_url_and_domain():
    assert assess_report("url", _data({"风险特征": "⚠ a；⚠ b；⚠ c"}))[0]["severity"] == "medium"
    assert assess_report("url", _data({"风险特征": "⚠ a"}))[0]["severity"] == "low"
    assert assess_report("domain", _data({"体检评级": "C（存在明确风险项，建议整改）"}))[0]["severity"] == "low"
    assert assess_report("domain", _data({"体检评级": "D（风险项较多，优先处理）"}))[0]["severity"] == "medium"


def test_assess_phone_and_user_none():
    assert assess_report("phone", _data({"运营商": "移动"})) == []
    assert assess_report("user", _data({"探活统计": "存在 1 / 未发现 2 / 无法判定 3"})) == []


def test_assess_mailbox_rules():
    risks = assess_report("mailbox", _data({"邮箱性质": "一次性邮箱（临时邮箱服务）"}))
    assert risks and risks[0]["severity"] == "low"
    risks = assess_report("mailbox", _data({"域名解析": "NXDOMAIN（域名不存在或已停用——该邮箱地址大概率无效）"}))
    assert risks and risks[0]["severity"] == "low"
    assert assess_report(
        "mailbox",
        _data({"邮箱性质": "个人免费邮箱", "邮箱画像": "网易 163 邮箱｜个人免费邮箱；可收信"}),
    ) == []
