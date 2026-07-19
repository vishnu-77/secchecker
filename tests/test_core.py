import pytest
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
    jwt_token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
    """
    f.write_text(content)
    findings = scan_file(str(f))

    assert "AWS Access Key" in findings
    assert "Password in Config" in findings
    assert "JWT Token" in findings

def test_scan_directory(tmp_path):
    """Test scanning a directory recursively."""
    # Create test files
    (tmp_path / "file1.py").write_text("password='test123'")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "file2.js").write_text("api_key: 'AIzaSyABC123'")
    
    results = scan_directory(str(tmp_path))
    
    assert len(results) >= 1  # Should find at least one file with secrets
    # Check if files are found (don't check specific paths due to OS differences)
    found_files = list(results.keys())
    assert any("file1.py" in path for path in found_files)

def test_scan_nonexistent_file():
    """Test scanning a file that doesn't exist."""
    findings = scan_file("nonexistent_file.txt")
    assert findings == {}

def test_scan_nonexistent_directory():
    """Test scanning a directory that doesn't exist."""
    with pytest.raises(FileNotFoundError):
        scan_directory("nonexistent_directory")

def test_scan_empty_directory(tmp_path):
    """Test scanning an empty directory."""
    results = scan_directory(str(tmp_path))
    assert results == {}

def test_get_scan_stats():
    """Test getting statistics about scan results."""
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
