import hashlib
import io
import json
import zipfile

from sentinel.core.pack import build_package, integrity


def _make_case(root, name, target="8.8.8.8", kind="ip"):
    case = root / name
    case.mkdir(parents=True)
    (case / "report.json").write_text(
        json.dumps({"kind": kind, "target": target, "created_at": "2026-10-11T00:00:00"}),
        encoding="utf-8",
    )
    (case / "report.md").write_text(f"# 报告 {name}\n", encoding="utf-8")
    files = [
        {"path": f, "sha256": hashlib.sha256((case / f).read_bytes()).hexdigest()}
        for f in ("report.json", "report.md")
    ]
    (case / "manifest.json").write_text(json.dumps({"files": files}), encoding="utf-8")
    return case


def _unzip(content: bytes) -> zipfile.ZipFile:
    return zipfile.ZipFile(io.BytesIO(content))


def test_build_package_contains_index_and_cases(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "c1")
    _make_case(cases, "c2")
    filename, content = build_package(cases)
    assert filename.startswith("sentinel-cases-") and filename.endswith(".zip")
    zf = _unzip(content)
    names = zf.namelist()
    root = names[0].split("/")[0]
    assert f"{root}/index.html" in names
    assert f"{root}/README.txt" in names
    assert f"{root}/cases/c1/report.md" in names
    assert f"{root}/cases/c1/report.html" in names
    assert f"{root}/cases/c2/report.json" in names
    index = zf.read(f"{root}/index.html").decode("utf-8")
    assert "c1" in index and "c2" in index


def test_pack_selected_only(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "keep")
    _make_case(cases, "drop")
    _, content = build_package(cases, ["keep"])
    names = _unzip(content).namelist()
    assert any("/cases/keep/" in n for n in names)
    assert not any("/cases/drop/" in n for n in names)


def test_pack_filters_unsafe_names(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "only")
    _, content = build_package(cases, ["../etc", "nope", "only"])
    names = _unzip(content).namelist()
    assert any("/cases/only/" in n for n in names)
    assert not any("etc" in n for n in names)


def test_pack_accepts_urlencoded_names(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "case+plus")
    _, content = build_package(cases, ["case%2Bplus"])
    names = _unzip(content).namelist()
    assert any("/cases/case+plus/" in n for n in names)


def test_pack_rejects_decoded_traversal(tmp_path):
    cases = tmp_path / "cases"
    _make_case(cases, "only")
    sibling = tmp_path / "secret"
    sibling.mkdir()
    (sibling / "loot.md").write_text("x", encoding="utf-8")
    _, content = build_package(cases, ["%2e%2e%2fsecret", "only"])
    names = _unzip(content).namelist()
    assert any("/cases/only/" in n for n in names)
    assert not any("secret" in n for n in names)


def test_pack_empty_raises(tmp_path):
    cases = tmp_path / "cases"
    cases.mkdir()
    try:
        build_package(cases)
        raise AssertionError("应当抛出 ValueError")
    except ValueError:
        pass


def test_integrity_detects_tamper(tmp_path):
    cases = tmp_path / "cases"
    case = _make_case(cases, "tampered")
    (case / "report.md").write_text("tampered", encoding="utf-8")
    all_ok, ok_count, total = integrity(case)
    assert all_ok is False and total == 2 and ok_count == 1
    _, content = build_package(cases, ["tampered"])
    zf = _unzip(content)
    index_name = next(n for n in zf.namelist() if n.endswith("index.html"))
    index = zf.read(index_name).decode("utf-8")
    assert "1/2" in index
