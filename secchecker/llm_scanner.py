"""LLM/AI Security scanner — scans source code for LLM vulnerability patterns."""
import re
import json
import os
from pathlib import Path
from typing import Dict, List

from secchecker.llm_patterns import LLM_PATTERNS
from secchecker.core import should_skip_directory, should_skip_file

LLM_RELEVANT_EXTENSIONS = {
    '.py', '.js', '.ts', '.tsx', '.jsx',
    '.ipynb', '.yaml', '.yml', '.json',
    '.env', '.toml', '.cfg', '.ini',
}


def _read_file(filepath):
    # type: (str) -> str
    """Read file content with encoding fallback. Returns None on failure."""
    for encoding in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, IOError):
            continue
    return None


def _scan_content(content):
    # type: (str) -> Dict[str, List[str]]
    """Scan text content against LLM_PATTERNS."""
    findings = {}
    for pattern_name, pattern_regex in LLM_PATTERNS.items():
        try:
            matches = re.findall(pattern_regex, content)
            if matches:
                flat = []
                for m in matches:
                    flat.append(m if isinstance(m, str) else ' '.join(m))
                # Deduplicate
                seen = set()
                deduped = []
                for item in flat:
                    if item not in seen:
                        seen.add(item)
                        deduped.append(item)
                findings[pattern_name] = deduped
        except re.error:
            pass
    return findings


def _scan_notebook(filepath):
    # type: (str) -> Dict[str, List[str]]
    """Extract source from Jupyter notebook cells and scan."""
    content = _read_file(filepath)
    if content is None:
        return {}
    try:
        nb = json.loads(content)
        cells = nb.get('cells', [])
        all_source = []
        for cell in cells:
            source = cell.get('source', [])
            if isinstance(source, list):
                all_source.append(''.join(source))
            elif isinstance(source, str):
                all_source.append(source)
        return _scan_content('\n'.join(all_source))
    except (ValueError, KeyError, TypeError):
        raw = _read_file(filepath)
        return _scan_content(raw) if raw else {}


def scan_file_llm(filepath):
    # type: (str) -> Dict[str, List[str]]
    """Scan a single file for LLM/AI security issues."""
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return {}

    if path.suffix.lower() not in LLM_RELEVANT_EXTENSIONS and path.name != '.env':
        return {}

    if should_skip_file(path):
        return {}

    if path.suffix.lower() == '.ipynb':
        return _scan_notebook(filepath)

    content = _read_file(filepath)
    if content is None:
        return {}
    return _scan_content(content)


def scan_directory_llm(directory):
    # type: (str) -> Dict[str, Dict[str, List[str]]]
    """Scan a directory recursively for LLM/AI security patterns."""
    if not os.path.exists(directory):
        raise FileNotFoundError("Directory not found: {}".format(directory))

    results = {}
    directory_path = Path(directory)

    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not should_skip_directory(Path(d))]

        for filename in files:
            file_path = root_path / filename
            if file_path.suffix.lower() not in LLM_RELEVANT_EXTENSIONS and file_path.name != '.env':
                continue
            findings = scan_file_llm(str(file_path))
            if findings:
                try:
                    rel = file_path.relative_to(directory_path)
                    results[str(rel)] = findings
                except ValueError:
                    results[str(file_path)] = findings

    return results
