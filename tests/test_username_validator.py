from sentinel.modules.username import handle_ok


def test_handle_ok_accepts_chinese_and_ascii():
    assert handle_ok("堃")
    assert handle_ok("张三丰")
    assert handle_ok("torvalds")
    assert handle_ok("a.b-c_d")


def test_handle_ok_rejects_bad_input():
    assert not handle_ok("")
    assert not handle_ok("bad name")
    assert not handle_ok("a/b")
    assert not handle_ok("a?b")
    assert not handle_ok("a" * 65)
    assert not handle_ok("a@b")
