import json
import xml.etree.ElementTree as ET
from pathlib import Path

# ------------------------------
# File-based report generation
# ------------------------------

def to_json(results: dict, output_file="secchecker_report.json"):
    """Generate JSON report file."""
    output_file = str(output_file)  # Ensure string path for cross-platform compatibility
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)
    return output_file

def to_markdown(results: dict, output_file="secchecker_report.md"):
    """Generate Markdown report file."""
    output_file = str(output_file)
    with open(output_file, "w") as f:
        f.write("# Secret Scan Report\n\n")
        for file, findings in results.items():
            f.write(f"## {file}\n")
            for category, matches in findings.items():
                f.write(f"- *{category}*: {matches}\n")
    return output_file

def to_xml(results: dict, output_file="secchecker_report.xml"):
    """Generate XML report file."""
    output_file = str(output_file)
    root = ET.Element("SecretScanReport")

    for file, findings in results.items():
        file_elem = ET.SubElement(root, "File", path=file)
        for category, matches in findings.items():
            category_elem = ET.SubElement(file_elem, "Category", name=category)
            for match in matches:
                match_elem = ET.SubElement(category_elem, "Match")
                match_elem.text = match

    tree = ET.ElementTree(root)
    tree.write(output_file, encoding="utf-8", xml_declaration=True)
    return output_file

# ------------------------------
# String-based report generation
# ------------------------------

def generate_report(data: dict, format: str):
    """Return the report as a string instead of writing to file."""
    format = format.lower()
    if format == 'json':
        return json.dumps(data, indent=2)
    elif format == 'md':
        return generate_markdown_report(data)
    elif format == 'xml':
        return generate_xml_report(data)
    else:
        raise ValueError(f'Unknown report format: {format}')

def generate_markdown_report(data: dict):
    """Return markdown report as string."""
    lines = ['# Secret Scan Report']
    for file, findings in data.items():
        lines.append(f'## {file}')
        for category, matches in findings.items():
            lines.append(f"- **{category}**: {matches}")
    return "\n".join(lines)

def generate_xml_report(data: dict):
    """Return XML report as string."""
    root = ET.Element("SecretScanReport")
    for file, findings in data.items():
        file_elem = ET.SubElement(root, "File", path=file)
        for category, matches in findings.items():
            category_elem = ET.SubElement(file_elem, "Category", name=category)
            for match in matches:
                match_elem = ET.SubElement(category_elem, "Match")
                match_elem.text = match
    return ET.tostring(root, encoding="unicode")
