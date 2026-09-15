import pytest
import secchecker.core as core
from secchecker.core import scan_file, scan_directory, get_scan_stats


def test_scan_file(tmp_path):
    """Test scanning a single file for secrets."""
    f = tmp_path / "test.txt"
    f.write_text("password='secret123'")
    findings = scan_file(str(f))
    assert "Password in Config" in findings


def test_scan_file_multiple_patterns(tmp_path):
    """Test scanning a file with multiple secret patterns."""
    f = tmp_path / "config.py"
    content = """
    AWS_ACCESS_KEY = 'AKIAIOSFODNN7XYZQMNB'
    password = 'mysecretpassword'
    jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature'
    """
    f.write_text(content)
    findings = scan_file(str(f))

    assert "AWS Access Key" in findings
    assert "Password in Config" in findings


def test_scan_directory(tmp_path):
    """Test scanning a directory recursively."""
    (tmp_path / "file1.py").write_text("password='test123'")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "file2.js").write_text("api_key: 'AIzaSyABC123'")

    results = scan_directory(str(tmp_path))

    assert len(results) >= 1
    found_files = list(results.keys())
    assert any("file1.py" in path for path in found_files)


def test_scan_nonexistent_file():
    """Test scanning a single missing path returns no findings."""
    findings = scan_file("nonexistent_file.txt")
    assert findings == {}


def test_scan_nonexistent_directory():
    """Directory scans retain the explicit not-found contract."""
    with pytest.raises(FileNotFoundError):
        scan_directory("nonexistent_directory")


def test_scan_empty_directory(tmp_path):
    results = scan_directory(str(tmp_path))
    assert results == {}


def test_get_scan_stats():
    mock_results = {
        "file1.py": {"Password in Config": ["password='test'"]},
        "file2.js": {"API Key": ["key1", "key2"], "JWT Token": ["token1"]}
    }

    stats = get_scan_stats(mock_results)

    assert stats["total_files"] == 2
    assert stats["total_secret_types"] == 3
    assert stats["total_matches"] == 4
    assert stats["pattern_breakdown"]["API Key"] == 2


def test_regression_q2_bearer_token_detected_end_to_end(tmp_path):
    """Bearer tokens must not be silently suppressed by JWT structural validation."""
    f = tmp_path / "auth.py"
    f.write_text('headers = {"Authorization": "Bearer 8f4kQ92mNp7xR3vTz1"}')
    findings = scan_file(str(f))
    assert "Bearer Token" in findings


def test_scan_file_extra_patterns(tmp_path):
    """extra_patterns (PII / custom_patterns) are opt-in additions to PATTERNS."""
    from secchecker.patterns import PII_PATTERNS

    f = tmp_path / "contact.py"
    f.write_text('contact = "a@b.com"')

    assert scan_file(str(f)) == {}
    findings = scan_file(str(f), extra_patterns=PII_PATTERNS)
    assert "Email" in findings


def test_capture_groups_return_complete_match_not_tuple(tmp_path):
    """A multi-capture regex must produce stable string evidence.

    Azure Storage Key contains two capture groups. ``re.findall`` previously
    returned tuples which were passed into the string validator, raising a
    TypeError that the outer scanner silently swallowed.
    """
    f = tmp_path / "azure.py"
    storage_key = "A" * 88
    f.write_text(
        'azure_storage_account_key = "{}"\n'.format(storage_key)
        + 'aws_key = "AKIAIOSFODNN7XYZQMNB"\n'
    )

    findings = scan_file(str(f))

    assert "Azure Storage Key" in findings
    assert isinstance(findings["Azure Storage Key"][0], str)
    assert storage_key in findings["Azure Storage Key"][0]
    # Scanning must continue after the multi-capture rule.
    assert "AWS Access Key" in findings


def test_single_capture_rule_keeps_full_evidence(tmp_path):
    """One capture group must not truncate evidence to the captured keyword."""
    f = tmp_path / "config.py"
    f.write_text("password='correct-horse-battery-staple'")

    findings = scan_file(str(f))

    evidence = findings["Password in Config"][0]
    assert evidence != "password"
    assert "correct-horse-battery-staple" in evidence


def test_unexpected_validator_failure_is_not_reported_as_clean(tmp_path, monkeypatch):
    """Internal analysis failures must propagate to the CLI's exit-2 path."""
    f = tmp_path / "config.py"
    f.write_text("password='correct-horse-battery-staple'")

    def broken_validator(pattern_name, match):
        raise RuntimeError("validator failed")

    monkeypatch.setattr(core, "_validate_match", broken_validator)

    with pytest.raises(RuntimeError, match="validator failed"):
        scan_file(str(f))
