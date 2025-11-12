import json
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any

# Severity mapping for different types of secrets
SEVERITY_MAP = {
    "AWS Access Key": "HIGH",
    "AWS Secret Key": "HIGH", 
    "AWS Session Token": "HIGH",
    "Google API Key": "HIGH",
    "Azure Client Secret": "HIGH",
    "Azure Storage Key": "HIGH",
    "RSA Private Key": "CRITICAL",
    "EC Private Key": "CRITICAL",
    "DSA Private Key": "CRITICAL",
    "PGP Private Key": "CRITICAL",
    "SSH Private Key": "CRITICAL",
    "Generic Private Key": "CRITICAL",
    "GitHub Token": "HIGH",
    "GitHub OAuth": "HIGH",
    "GitLab Token": "HIGH",
    "JWT Token": "MEDIUM",
    "Bearer Token": "MEDIUM",
    "Basic Auth": "MEDIUM",
    "Postgres URI": "HIGH",
    "MySQL URI": "HIGH",
    "MongoDB URI": "HIGH",
    "Redis URI": "HIGH",
    "SQL Server Connection": "HIGH",
    "Oracle Connection": "HIGH",
    "Credit Card": "CRITICAL",
    "Social Security Number": "CRITICAL",
    "Bitcoin Private Key": "HIGH",
    "Ethereum Private Key": "HIGH",
    "HTTP URL with Credentials": "MEDIUM",
    "FTP URL with Credentials": "MEDIUM",
    "Slack Token": "HIGH",
    "Discord Bot Token": "HIGH",
    "Telegram Bot Token": "HIGH",
    "Password in Config": "MEDIUM",
    "Database Password": "HIGH",
    "Admin Password": "HIGH"
}

def get_severity(pattern_name: str) -> str:
    """Get severity level for a pattern."""
    return SEVERITY_MAP.get(pattern_name, "LOW")

def get_scan_metadata() -> Dict[str, Any]:
    """Get metadata about the scan."""
    return {
        "timestamp": datetime.now().isoformat(),
        "version": "0.2.0",
        "tool": "secchecker"
    }

# ------------------------------
# File-based report generation
# ------------------------------

def to_json(results: Dict[str, Dict[str, List[str]]], output_file="secchecker_report.json") -> str:
    """Generate enhanced JSON report file with metadata and severity."""
    output_file = str(output_file)
    
    # Add metadata and severity information
    enhanced_results = {
        "metadata": get_scan_metadata(),
        "summary": {
            "total_files": len(results),
            "total_secrets": sum(len(findings) for findings in results.values()),
            "total_matches": sum(len(matches) for findings in results.values() for matches in findings.values()),
            "severity_counts": {}
        },
        "findings": {}
    }
    
    # Process findings with severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    
    for file, findings in results.items():
        enhanced_results["findings"][file] = {}
        for pattern_name, matches in findings.items():
            severity = get_severity(pattern_name)
            severity_counts[severity] += len(matches)
            
            enhanced_results["findings"][file][pattern_name] = {
                "matches": matches,
                "severity": severity,
                "count": len(matches)
            }
    
    enhanced_results["summary"]["severity_counts"] = severity_counts
    
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(enhanced_results, f, indent=4, ensure_ascii=False)
    return output_file

def to_markdown(results: Dict[str, Dict[str, List[str]]], output_file="secchecker_report.md") -> str:
    """Generate enhanced Markdown report file."""
    output_file = str(output_file)
    
    metadata = get_scan_metadata()
    
    # Calculate statistics
    total_files = len(results)
    total_secrets = sum(len(findings) for findings in results.values())
    total_matches = sum(len(matches) for findings in results.values() for matches in findings.values())
    
    # Count by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for findings in results.values():
        for pattern_name, matches in findings.items():
            severity = get_severity(pattern_name)
            severity_counts[severity] += len(matches)
    
    with open(output_file, "w", encoding="utf-8") as f:
        # Header
        f.write("# 🔍 Secret Scan Report\n\n")
        f.write(f"**Generated:** {metadata['timestamp']}  \n")
        f.write(f"**Tool:** {metadata['tool']} v{metadata['version']}  \n\n")
        
        # Summary
        f.write("## 📊 Summary\n\n")
        f.write(f"- **Files Scanned:** {total_files}\n")
        f.write(f"- **Secret Types Found:** {total_secrets}\n")
        f.write(f"- **Total Matches:** {total_matches}\n\n")
        
        # Severity breakdown
        f.write("### 🚨 Severity Breakdown\n\n")
        for severity, count in severity_counts.items():
            if count > 0:
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                f.write(f"- {emoji} **{severity}:** {count}\n")
        f.write("\n")
        
        # Detailed findings
        f.write("## 🔎 Detailed Findings\n\n")
        for file, findings in results.items():
            f.write(f"### 📄 `{file}`\n\n")
            for pattern_name, matches in findings.items():
                severity = get_severity(pattern_name)
                emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
                f.write(f"- {emoji} **{pattern_name}** ({severity}): {len(matches)} match(es)\n")
                for i, match in enumerate(matches, 1):
                    # Truncate long matches for readability
                    display_match = match[:100] + "..." if len(match) > 100 else match
                    f.write(f"  {i}. `{display_match}`\n")
                f.write("\n")
    
    return output_file

def to_xml(results: Dict[str, Dict[str, List[str]]], output_file="secchecker_report.xml") -> str:
    """Generate enhanced XML report file with proper formatting."""
    output_file = str(output_file)
    
    metadata = get_scan_metadata()
    
    # Create root element with metadata
    root = ET.Element("SecretScanReport")
    root.set("timestamp", metadata["timestamp"])
    root.set("version", metadata["version"])
    root.set("tool", metadata["tool"])
    
    # Summary section
    summary = ET.SubElement(root, "Summary")
    summary.set("totalFiles", str(len(results)))
    summary.set("totalSecrets", str(sum(len(findings) for findings in results.values())))
    summary.set("totalMatches", str(sum(len(matches) for findings in results.values() for matches in findings.values())))
    
    # Severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for findings in results.values():
        for pattern_name, matches in findings.items():
            severity = get_severity(pattern_name)
            severity_counts[severity] += len(matches)
    
    severity_elem = ET.SubElement(summary, "SeverityCounts")
    for severity, count in severity_counts.items():
        sev_elem = ET.SubElement(severity_elem, "Severity")
        sev_elem.set("level", severity)
        sev_elem.set("count", str(count))
    
    # Findings section
    findings_elem = ET.SubElement(root, "Findings")
    
    for file, findings in results.items():
        file_elem = ET.SubElement(findings_elem, "File")
        file_elem.set("path", file)
        file_elem.set("secretCount", str(len(findings)))
        
        for pattern_name, matches in findings.items():
            category_elem = ET.SubElement(file_elem, "Category")
            category_elem.set("name", pattern_name)
            category_elem.set("severity", get_severity(pattern_name))
            category_elem.set("matchCount", str(len(matches)))
            
            for match in matches:
                match_elem = ET.SubElement(category_elem, "Match")
                match_elem.text = match
    
    # Write with proper formatting
    ET.indent(root, space="  ")
    tree = ET.ElementTree(root)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    
    return output_file

# ------------------------------
# String-based report generation
# ------------------------------

def generate_report(data: Dict[str, Dict[str, List[str]]], format_type: str) -> str:
    """Return the report as a string instead of writing to file."""
    format_type = format_type.lower()
    if format_type == 'json':
        return generate_json_report(data)
    elif format_type == 'md':
        return generate_markdown_report(data)
    elif format_type == 'xml':
        return generate_xml_report(data)
    else:
        raise ValueError(f'Unknown report format: {format_type}')

def generate_json_report(data: Dict[str, Dict[str, List[str]]]) -> str:
    """Return JSON report as string with enhanced metadata."""
    enhanced_results = {
        "metadata": get_scan_metadata(),
        "summary": {
            "total_files": len(data),
            "total_secrets": sum(len(findings) for findings in data.values()),
            "total_matches": sum(len(matches) for findings in data.values() for matches in findings.values())
        },
        "findings": {}
    }
    
    for file, findings in data.items():
        enhanced_results["findings"][file] = {}
        for pattern_name, matches in findings.items():
            enhanced_results["findings"][file][pattern_name] = {
                "matches": matches,
                "severity": get_severity(pattern_name),
                "count": len(matches)
            }
    
    return json.dumps(enhanced_results, indent=2, ensure_ascii=False)

def generate_markdown_report(data: Dict[str, Dict[str, List[str]]]) -> str:
    """Return markdown report as string."""
    lines = ['# 🔍 Secret Scan Report', '']
    metadata = get_scan_metadata()
    lines.append(f"**Generated:** {metadata['timestamp']}")
    lines.append('')
    
    for file, findings in data.items():
        lines.append(f'## 📄 {file}')
        for pattern_name, matches in findings.items():
            severity = get_severity(pattern_name)
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[severity]
            lines.append(f"- {emoji} **{pattern_name}** ({severity}): {matches}")
    
    return "\n".join(lines)

def generate_xml_report(data: Dict[str, Dict[str, List[str]]]) -> str:
    """Return XML report as string with proper formatting."""
    metadata = get_scan_metadata()
    
    root = ET.Element("SecretScanReport")
    root.set("timestamp", metadata["timestamp"])
    root.set("version", metadata["version"])
    
    for file, findings in data.items():
        file_elem = ET.SubElement(root, "File")
        file_elem.set("path", file)
        
        for pattern_name, matches in findings.items():
            category_elem = ET.SubElement(file_elem, "Category")
            category_elem.set("name", pattern_name)
            category_elem.set("severity", get_severity(pattern_name))
            
            for match in matches:
                match_elem = ET.SubElement(category_elem, "Match")
                match_elem.text = match
    
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="unicode")
