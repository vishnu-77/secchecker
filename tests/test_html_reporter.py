import pytest
from secchecker.html_reporter import generate_html_report, to_html

SAMPLE = {
    "src/config.py": {
        "AWS Access Key": ["AKIAIOSFODNN7EXAMPLE"],
        "Password in Config": ["password='test'"],
    }
}


def test_html_structure():
    report = generate_html_report(SAMPLE)
    assert "<!DOCTYPE html>" in report
    assert "<html" in report
    assert "</html>" in report


def test_html_self_contained():
    report = generate_html_report(SAMPLE)
    assert "<style>" in report
    assert 'rel="stylesheet"' not in report
    assert "<script src=" not in report


def test_html_contains_findings():
    report = generate_html_report(SAMPLE)
    assert "AWS Access Key" in report
    assert "Password in Config" in report


def test_html_has_severity():
    report = generate_html_report(SAMPLE)
    assert any(s in report for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))


def test_html_empty_results():
    report = generate_html_report({})
    assert "<!DOCTYPE html>" in report
    assert "No security findings" in report


def test_html_scan_type_shown():
    report = generate_html_report(SAMPLE, scan_type="llm")
    assert "llm" in report


def test_to_html_writes_file(tmp_path):
    out = tmp_path / "report.html"
    to_html(SAMPLE, str(out))
    assert out.exists()
    content = out.read_text(encoding='utf-8')
    assert "<!DOCTYPE html>" in content
    assert "AWS Access Key" in content


def test_html_escapes_xss():
    results = {"file.py": {"Test": ["<script>alert(1)</script>"]}}
    report = generate_html_report(results)
    assert "<script>alert" not in report
    assert "&lt;script&gt;" in report
