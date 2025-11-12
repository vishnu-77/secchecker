import pytest
import json
import xml.etree.ElementTree as ET
from secchecker.reporter import (
    to_json, to_markdown, to_xml, 
    generate_report, get_severity,
    generate_json_report, generate_markdown_report, generate_xml_report
)

def test_to_json(tmp_path):
    """Test JSON report file generation."""
    results = {"file.txt": {"Password in Config": ["password='123'"]}}
    json_file = to_json(results, tmp_path / "out.json")
    
    assert str(json_file).endswith("out.json")
    
    # Verify content
    with open(json_file) as f:
        data = json.load(f)
    
    assert "metadata" in data
    assert "summary" in data
    assert "findings" in data
    assert data["summary"]["total_files"] == 1

def test_to_markdown(tmp_path):
    """Test Markdown report file generation."""
    results = {"file.txt": {"Password in Config": ["password='123'"]}}
    md_file = to_markdown(results, tmp_path / "out.md")
    
    assert str(md_file).endswith("out.md")
    
    # Verify content with proper encoding
    with open(md_file, encoding='utf-8') as f:
        content = f.read()
    
    assert "Secret Scan Report" in content
    assert "Password in Config" in content
    assert "MEDIUM" in content  # Severity level

def test_to_xml(tmp_path):
    """Test XML report file generation."""
    results = {"file.txt": {"Password in Config": ["password='123'"]}}
    xml_file = to_xml(results, tmp_path / "out.xml")
    
    assert str(xml_file).endswith("out.xml")
    
    # Verify content
    tree = ET.parse(xml_file)
    root = tree.getroot()
    
    assert root.tag == "SecretScanReport"
    assert root.get("tool") == "secchecker"
    assert len(root.find("Findings")) >= 1

def test_generate_string_reports():
    """Test string-based report generation."""
    results = {"file.txt": {"Password in Config": ["password='123'"]}}
    
    # Test JSON string report
    json_report = generate_report(results, "json")
    assert isinstance(json_report, str)
    data = json.loads(json_report)
    assert "metadata" in data
    
    # Test Markdown string report
    md_report = generate_report(results, "md")
    assert isinstance(md_report, str)
    assert "Secret Scan Report" in md_report
    
    # Test XML string report
    xml_report = generate_report(results, "xml")
    assert isinstance(xml_report, str)
    assert "<SecretScanReport" in xml_report

def test_get_severity():
    """Test severity mapping."""
    assert get_severity("AWS Access Key") == "HIGH"
    assert get_severity("RSA Private Key") == "CRITICAL"
    assert get_severity("Password in Config") == "MEDIUM"
    assert get_severity("Unknown Pattern") == "LOW"

def test_invalid_report_format():
    """Test handling of invalid report format."""
    results = {"file.txt": {"Password in Config": ["password='123'"]}}
    
    with pytest.raises(ValueError):
        generate_report(results, "invalid_format")

def test_empty_results():
    """Test report generation with empty results."""
    results = {}
    
    json_report = generate_json_report(results)
    data = json.loads(json_report)
    assert data["summary"]["total_files"] == 0
    
    md_report = generate_markdown_report(results)
    assert "Secret Scan Report" in md_report
    
    xml_report = generate_xml_report(results)
    assert "<SecretScanReport" in xml_report
