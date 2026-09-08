import pytest
import json
from secchecker.sarif_reporter import generate_sarif_report, to_sarif

SAMPLE = {
    "src/config.py": {
        "AWS Access Key": ["AKIAIOSFODNN7EXAMPLE"],
        "Password in Config": ["password='test'"],
    },
    "src/main.py": {
        "JWT Token": ["eyJhbGciOiJIUzI1NiJ9.test.sig"],
    },
}


def test_sarif_valid_json():
    data = json.loads(generate_sarif_report(SAMPLE))
    assert isinstance(data, dict)


def test_sarif_version():
    data = json.loads(generate_sarif_report(SAMPLE))
    assert data["version"] == "2.1.0"
    assert "json.schemastore.org/sarif" in data["$schema"]


def test_sarif_tool_name():
    data = json.loads(generate_sarif_report(SAMPLE))
    assert data["runs"][0]["tool"]["driver"]["name"] == "secchecker"


def test_sarif_has_rules():
    data = json.loads(generate_sarif_report(SAMPLE))
    ids = [r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]]
    assert "AWS Access Key" in ids
    assert "Password in Config" in ids


def test_sarif_has_results():
    data = json.loads(generate_sarif_report(SAMPLE))
    assert len(data["runs"][0]["results"]) >= 3


def test_sarif_high_severity_is_error():
    data = json.loads(generate_sarif_report({"f.py": {"AWS Access Key": ["AKIA..."]}}))
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_sarif_forward_slashes():
    results = {"src\\config\\file.py": {"AWS Access Key": ["AKIA..."]}}
    data = json.loads(generate_sarif_report(results))
    uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_sarif_empty_results():
    data = json.loads(generate_sarif_report({}))
    assert data["runs"][0]["results"] == []


def test_to_sarif_file(tmp_path):
    out = tmp_path / "report.sarif"
    path = to_sarif(SAMPLE, str(out))
    assert out.exists()
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"


def test_sarif_region_reports_the_real_match_line(tmp_path):
    src = tmp_path / "app.py"
    src.write_text(
        "import os\n"
        "\n"
        "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n",
        encoding="utf-8",
    )
    results = {str(src): {"AWS Access Key": ["AKIAIOSFODNN7EXAMPLE"]}}
    data = json.loads(generate_sarif_report(results))
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 3


def test_sarif_region_falls_back_to_line_1_when_file_unreadable():
    # SAMPLE's paths don't exist on disk - must not crash, must still emit a
    # valid (if imprecise) region rather than erroring the whole report.
    data = json.loads(generate_sarif_report(SAMPLE))
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
