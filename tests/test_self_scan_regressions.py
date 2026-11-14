"""Regression tests for self-scans and GitHub Action supply-chain checks."""

from pathlib import Path
import pytest
from secchecker.config import is_path_excluded, load_config
from secchecker.core import scan_file
from secchecker.devsecops_scanner import scan_file_devsecops


def scan_text(tmp_path, content):
    path = tmp_path / "sample.py"
    path.write_text(content, encoding="utf-8")
    return scan_file(str(path))


@pytest.mark.parametrize(("rule", "text"), [
    ("Password in Config", "password = 'N3wPr0dValue9!'"),
    ("Database Password", "db_password = 'N3wPr0dValue9!'"),
    ("Admin Password", "admin_password = 'N3wPr0dValue9!'"),
    ("Generic Secret", "token = '" + ("Ab3dEf7G" * 3) + "'"),
    ("AWS Secret Key", "aws_secret = '" + ("Ab3dEf7G" * 5) + "'"),
    ("AWS Session Token", "aws_session = '" + ("Ab3dEf7G" * 3) + "'"),
    ("Azure Client Secret", "azure_client = '" + ("Ab3dEf7G" * 5) + "'"),
    ("Azure Storage Key", "azure_storage_key = '" + ("Ab3dEf7G" * 11)[:88] + "'"),
    ("Hex Encoded Secret", "secret = '" + ("abcdef1234567890" * 2) + "'"),
])
def test_capture_groups_return_whole_assignment(tmp_path, rule, text):
    result = scan_text(tmp_path, text)
    assert rule in result, (rule, result)
    assert any("=" in value and len(value) > 12 for value in result[rule]), result[rule]


def test_placeholders_checked_after_full_match_extraction(tmp_path):
    assert "Password in Config" not in scan_text(tmp_path, "password = 'changeme'")
    assert "Password in Config" in scan_text(tmp_path, "password = 'N3wPr0dValue9!'")


def test_custom_regex_capture_reports_whole_match(tmp_path):
    path = tmp_path / "fixture.txt"
    path.write_text("ticket: 778891", encoding="utf-8")
    assert scan_file(str(path), extra_patterns={"Ticket": r"ticket:\s*(\d+)"})["Ticket"] == ["ticket: 778891"]


def test_basic_auth_validates_decoded_user_and_password(tmp_path):
    assert "Basic Auth" not in scan_text(tmp_path, "basic helpers and BasicAuth")
    assert "Basic Auth" not in scan_text(tmp_path, "Authorization: Basic dXNlcm5hbWU=")
    assert "Basic Auth" in scan_text(tmp_path, "Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==")


def test_bearer_scheme_excludes_plain_words_and_repetition(tmp_path):
    assert "Bearer Token" not in scan_text(tmp_path, "the bearer token must be supplied")
    assert "Bearer Token" not in scan_text(tmp_path, "Authorization: Bearer aaaaaaaaaaaaaaaaaaaaaaaa")
    assert "Bearer Token" in scan_text(tmp_path, "Authorization: Bearer 8f4kQ92mNp7xR3vTz1")


def test_userinfo_url_must_not_cross_path_or_query(tmp_path):
    assert "HTTP URL with Credentials" not in scan_text(
        tmp_path, "https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400")
    assert "HTTP URL with Credentials" in scan_text(
        tmp_path, "https://alice:N3wPr0dValue9@api.internal.io/v1")
    assert "FTP URL with Credentials" not in scan_text(
        tmp_path, "ftp://host/path?mode=a:b@other")


def test_case_sensitive_token_prefixes(tmp_path):
    assert "AWS Access Key" not in scan_text(tmp_path, "akia" + "A1B2C3D4" * 4)
    assert "Twilio Account SID" not in scan_text(tmp_path, "ac" + "A1B2C3D4" * 4)
    assert "AWS Access Key" in scan_text(tmp_path, "AK" + "IA" + "A1B2C3D4" * 4)


@pytest.mark.parametrize("ref", [
    "actions/setup-python@v5",
    "github/codeql-action/upload-sarif@v3",
])
def test_unpinned_actions_are_detected(tmp_path, ref):
    path = tmp_path / "workflow.yml"
    path.write_text("steps:\n  - uses: " + ref + "\n", encoding="utf-8")
    assert "CI - Unpinned GitHub Action" in scan_file_devsecops(str(path))


def test_sha_pinned_action_is_accepted(tmp_path):
    path = tmp_path / "workflow.yml"
    path.write_text(
        "steps:\n  - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5\n",
        encoding="utf-8",
    )
    assert "CI - Unpinned GitHub Action" not in scan_file_devsecops(str(path))


def test_self_scan_exclusions():
    cfg = load_config(str(Path(__file__).resolve().parents[1] / ".secchecker.yml"))
    excluded = (
        "bench/agentsecbench/cases/FP-01.md",
        "bench/agentsecbench/raw_results/example.json",
        "bench/agentsecbench/raw_results_after_fix/example.json",
        "brand/scenarios.py",
        "secchecker/llm_scanner.py",
        "dev-setup.sh",
        "dev-setup.bat",
    )
    for path in excluded:
        assert is_path_excluded(path, cfg["exclude_paths"]), path
    assert not is_path_excluded("action.yml", cfg["exclude_paths"])
    assert not is_path_excluded("secchecker/core.py", cfg["exclude_paths"])


def test_composite_action_uses_immutable_sha_and_safe_input_transport():
    action = (Path(__file__).resolve().parents[1] / "action.yml").read_text(encoding="utf-8")
    assert "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065" in action
    assert "github/codeql-action/upload-sarif@9418214df1f2c4b8128c770156c409013b07d6b9" in action
    assert 'secchecker "' + "$" + "{{ inputs.path }}" not in action
    assert 'pip install "secchecker==' + "$" + "{{ inputs.version }}" not in action
