from sentinel.core.tasks import TaskManager


def test_patrol_report_includes_ai(tmp_path):
    manager = TaskManager(tmp_path)
    patrol_dir = manager._pack_patrol(None, None, "host", ai_text="测试 AI 解读内容", ai_error=None)
    report_md = (patrol_dir / "report.md").read_text(encoding="utf-8")
    assert "AI 解读" in report_md
    assert "测试 AI 解读内容" in report_md
    report_json = (patrol_dir / "report.json").read_text(encoding="utf-8")
    assert "测试 AI 解读内容" in report_json


def test_patrol_report_marks_ai_failure(tmp_path):
    manager = TaskManager(tmp_path)
    patrol_dir = manager._pack_patrol(None, None, "host", ai_text=None, ai_error="接口超时")
    report_md = (patrol_dir / "report.md").read_text(encoding="utf-8")
    assert "AI 解读失败" in report_md
    assert "接口超时" in report_md
