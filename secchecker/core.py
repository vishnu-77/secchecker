import re
from pathlib import Path
from .patterns import PATTERNS

def scan_file(filepath: str) -> dict:
    findings = {}
    try:
        with open(filepath, "r", errors="ignore") as f:
            content = f.read()
            for name, pattern in PATTERNS.items():
                matches = re.findall(pattern, content)
                if matches:
                    findings[name] = matches
    except Exception:
        pass
    return findings

def scan_directory(directory: str) -> dict:
    results = {}
    for path in Path(directory).rglob("*"):
        if path.is_file():
            file_findings = scan_file(str(path))
            if file_findings:
                results[str(path)] = file_findings
    return results
