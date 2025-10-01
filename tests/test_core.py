from secchecker.core import scan_file

def test_scan_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_text("password='secret123'")
    findings = scan_file(str(f))
    assert "Password in Config" in findings
