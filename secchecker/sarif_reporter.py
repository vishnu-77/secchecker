"""SARIF 2.1.0 report generator for secchecker."""
import json
import os
from datetime import datetime
from typing import Any, Dict, List

try:
    from secchecker.reporter import get_severity
    from secchecker import __version__ as _VERSION
except ImportError:
    _VERSION = "0.3.0"

    def get_severity(name):
        return "MEDIUM"

SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

SARIF_SECURITY_SEVERITY = {
    "CRITICAL": "9.8",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def _normalize_path(filepath):
    # type: (str) -> str
    """Use forward slashes for GitHub Security tab compatibility."""
    return filepath.replace('\\', '/')


def _build_rules(pattern_names):
    # type: (List[str]) -> List[Dict[str, Any]]
    """Build SARIF rules array from pattern names."""
    rules = []
    seen = set()
    for name in pattern_names:
        if name in seen:
            continue
        seen.add(name)
        severity = get_severity(name)
        level = SARIF_LEVEL_MAP.get(severity, "warning")
        rules.append({
            "id": name,
            "name": name.replace(" ", "").replace("-", "").replace("/", ""),
            "shortDescription": {"text": name},
            "fullDescription": {"text": "Detected: {}".format(name)},
            "defaultConfiguration": {"level": level},
            "properties": {
                "tags": ["security", severity.lower()],
                "security-severity": SARIF_SECURITY_SEVERITY.get(severity, "5.0"),
            },
        })
    return rules


def _build_results(results):
    # type: (Dict[str, Dict[str, List[str]]]) -> List[Dict[str, Any]]
    """Build SARIF results array."""
    sarif_results = []
    for filepath, patterns in results.items():
        uri = _normalize_path(filepath)
        for pattern_name, matches in patterns.items():
            severity = get_severity(pattern_name)
            level = SARIF_LEVEL_MAP.get(severity, "warning")
            msg = "{} ({} occurrence{})".format(
                pattern_name, len(matches), "s" if len(matches) != 1 else ""
            )
            sarif_results.append({
                "ruleId": pattern_name,
                "level": level,
                "message": {"text": msg},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": uri,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": 1},
                    }
                }],
                "properties": {
                    "severity": severity,
                    "matchCount": len(matches),
                },
            })
    return sarif_results


def generate_sarif_report(results):
    # type: (Dict[str, Dict[str, List[str]]]) -> str
    """Generate a SARIF 2.1.0 report as a JSON string."""
    all_patterns = []
    for patterns in results.values():
        for name in patterns:
            if name not in all_patterns:
                all_patterns.append(name)

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "secchecker",
                    "version": _VERSION,
                    "informationUri": "https://github.com/vishnu-77/secchecker",
                    "rules": _build_rules(all_patterns),
                }
            },
            "results": _build_results(results),
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            }],
        }]
    }
    return json.dumps(sarif, indent=2)


def to_sarif(results, output_file="secchecker_report.sarif"):
    # type: (Dict[str, Dict[str, List[str]]], str) -> str
    """Write SARIF 2.1.0 report to file. Returns file path."""
    report = generate_sarif_report(results)
    output_path = str(output_file)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(report)
    return output_path
