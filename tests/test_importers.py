import json

from sentinel.core.assets import AssetStore
from sentinel.core.findings import FindingStore
from sentinel.core.importers import import_file, parse_csv, parse_nuclei_jsonl


def test_parse_nuclei_jsonl():
    line = json.dumps(
        {
            "template-id": "t1",
            "info": {"name": "Demo Vuln", "severity": "high"},
            "host": "1.2.3.4",
            "matched-at": "http://1.2.3.4/x",
        }
    )
    items = parse_nuclei_jsonl(line + "\n")
    assert len(items) == 1
    assert items[0]["severity"] == "high"
    assert "Demo Vuln" in items[0]["title"]
    assert items[0]["target"] == "1.2.3.4"


def test_parse_csv():
    text = "title,severity,target,detail\nCSV 发现,medium,example.com,示例\n"
    items = parse_csv(text)
    assert len(items) == 1
    assert items[0]["severity"] == "medium"
    assert items[0]["target"] == "example.com"


def test_import_dedupe(tmp_path):
    findings = FindingStore(tmp_path)
    assets = AssetStore(tmp_path)
    path = tmp_path / "results.jsonl"
    line = json.dumps({"template-id": "t1", "info": {"name": "Demo", "severity": "low"}, "host": "1.2.3.4"})
    path.write_text(line + "\n", encoding="utf-8")
    first = import_file(path, "nuclei", findings, assets)
    assert first["imported"] == 1
    second = import_file(path, "nuclei", findings, assets)
    assert second["skipped"] == 1
    assert assets.list()
