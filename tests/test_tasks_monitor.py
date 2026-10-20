from sentinel.core.tasks import Task, TaskManager


def test_digest_state_roundtrip(tmp_path):
    manager = TaskManager(tmp_path)
    assert manager._last_digest_date() == ""
    manager._set_last_digest_date("2026-10-12")
    assert manager._last_digest_date() == "2026-10-12"


def test_last_patrol_epoch(tmp_path):
    manager = TaskManager(tmp_path)
    assert manager._last_patrol_epoch() is None
    task = Task(id="p1", kind="patrol", title="x")
    task.status = "done"
    task.finished = "2026-10-11 12:00:00"
    manager._tasks.append(task)
    assert manager._last_patrol_epoch() is not None


def test_busy_helper(tmp_path):
    manager = TaskManager(tmp_path)
    assert manager._busy() is False
    task = Task(id="d1", kind="digest", title="x")
    task.status = "running"
    manager._tasks.append(task)
    assert manager._busy() is True
    assert manager._busy("digest") is True
    assert manager._busy("patrol") is False
