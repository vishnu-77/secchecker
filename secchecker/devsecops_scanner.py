"""DevSecOps scanner — scans infrastructure configs for security misconfigurations."""
import re
import os
import fnmatch
from pathlib import Path
from typing import Dict, List

from secchecker.devsecops_patterns import DEVSECOPS_PATTERNS, FILE_TYPE_FILTER
from secchecker.core import should_skip_directory

DEVSECOPS_EXTENSIONS = {'.tf', '.tfvars', '.yaml', '.yml', '.sh', '.dockerfile'}
DEVSECOPS_EXACT_NAMES = {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}


def matches_file_filter(filepath, pattern_name):
    # type: (str, str) -> bool
    """Check if a pattern's FILE_TYPE_FILTER applies to this file."""
    if pattern_name not in FILE_TYPE_FILTER:
        return True
    path = Path(filepath)
    for f in FILE_TYPE_FILTER[pattern_name]:
        if fnmatch.fnmatch(path.name, f):
            return True
    return False


def _is_devsecops_file(filepath):
    # type: (str) -> bool
    """Return True if this file should be scanned for DevSecOps patterns."""
    path = Path(filepath)
    if path.name in DEVSECOPS_EXACT_NAMES:
        return True
    return path.suffix.lower() in DEVSECOPS_EXTENSIONS


def _read_file(filepath):
    # type: (str) -> str
    """Read file with encoding fallback. Returns None on failure."""
    for encoding in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, IOError):
            continue
    return None


def scan_file_devsecops(filepath):
    # type: (str) -> Dict[str, List[str]]
    """Scan a single file for DevSecOps misconfigurations."""
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return {}
    try:
        if path.stat().st_size > 10 * 1024 * 1024:
            return {}
    except OSError:
        return {}

    content = _read_file(filepath)
    if content is None:
        return {}

    findings = {}
    for pattern_name, pattern_regex in DEVSECOPS_PATTERNS.items():
        if not matches_file_filter(filepath, pattern_name):
            continue
        try:
            matches = re.findall(pattern_regex, content)
            if matches:
                flat = []
                for m in matches:
                    flat.append(m if isinstance(m, str) else ' '.join(m))
                seen = set()
                deduped = [x for x in flat if not (x in seen or seen.add(x))]
                findings[pattern_name] = deduped
        except re.error:
            pass
    return findings


def scan_directory_devsecops(directory):
    # type: (str) -> Dict[str, Dict[str, List[str]]]
    """Scan a directory for DevSecOps misconfigurations."""
    if not os.path.exists(directory):
        raise FileNotFoundError("Directory not found: {}".format(directory))

    results = {}
    directory_path = Path(directory)

    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not should_skip_directory(Path(d))]

        for filename in files:
            file_path = root_path / filename
            if not _is_devsecops_file(str(file_path)):
                continue
            findings = scan_file_devsecops(str(file_path))
            if findings:
                try:
                    rel = file_path.relative_to(directory_path)
                    results[str(rel)] = findings
                except ValueError:
                    results[str(file_path)] = findings

    return results
