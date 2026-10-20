import json

from sentinel.core.case import ARCHIVE_DIRNAME, archive_cases, delete_archived, restore_cases


def _make_case(root, name):
    case = root / name
    case.mkdir(parents=True)
    (case / "report.json").write_text(json.dumps({"kind": "ip", "target": "8.8.8.8"}), encoding="utf-8")
    return case


def test_archive_restore_roundtrip(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "c1")
    result = archive_cases(cases, ["c1", "nope", "../evil"])
    assert result["archived"] == ["c1"]
    assert len(result["skipped"]) == 2
    assert not (cases / "c1").exists()
    assert (cases / ARCHIVE_DIRNAME / "c1").is_dir()
    back = restore_cases(cases, ["c1"])
    assert back["restored"] == ["c1"]
    assert (cases / "c1").is_dir()
    assert not (cases / ARCHIVE_DIRNAME / "c1").exists()


def test_delete_requires_confirm(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "c1")
    archive_cases(cases, ["c1"])
    denied = delete_archived(cases, ["c1"], confirm="")
    assert denied["deleted"] == []
    assert (cases / ARCHIVE_DIRNAME / "c1").is_dir()
    done = delete_archived(cases, ["c1"], confirm="DELETE")
    assert done["deleted"] == ["c1"]
    assert not (cases / ARCHIVE_DIRNAME / "c1").exists()


def test_archive_conflict_skipped(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "dup")
    archive_cases(cases, ["dup"])
    _make_case(cases, "dup")
    again = archive_cases(cases, ["dup"])
    assert again["archived"] == []
    assert "已存在" in again["skipped"][0]


def test_delete_outside_archive_is_skipped(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "live")
    result = delete_archived(cases, ["live", "../.."], confirm="DELETE")
    assert result["deleted"] == []
    assert (cases / "live").is_dir()
