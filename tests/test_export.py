from sentinel.core.case import save_case
from sentinel.core.export import export_case
from sentinel.core.models import Confidence, TriageReport


def _make_case(tmp_path):
    report = TriageReport(kind="ip", target="8.8.8.8")
    report.add("国家", "United States (US)", Confidence.LIKELY, "ipwho.is")
    report.add("ASN", "AS15169", Confidence.LIKELY, "ipwho.is")
    report.note("测试备注")
    return save_case(report, tmp_path)


def test_export_html(tmp_path):
    case_dir = _make_case(tmp_path)
    filename, content = export_case(case_dir, "html")
    assert filename.endswith(".html")
    assert "8.8.8.8" in content
    assert "AS15169" in content
    assert "SHA-256" in content
    assert "校验通过" in content


def test_export_markdown(tmp_path):
    case_dir = _make_case(tmp_path)
    filename, content = export_case(case_dir, "md")
    assert filename.endswith(".md")
    assert "8.8.8.8" in content


def test_export_brief_and_evidence(tmp_path):
    case_dir = _make_case(tmp_path)
    brief_name, brief = export_case(case_dir, "html", template="brief")
    assert brief_name.endswith("-brief.html")
    assert "简报" in brief
    assert "打印" in brief
    evidence_name, evidence = export_case(case_dir, "html", template="evidence")
    assert evidence_name.endswith("-evidence.html")
    assert "证据版" in evidence
    assert "SHA-256" in evidence
