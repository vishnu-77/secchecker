import re
import os
import json
from pathlib import Path
from typing import Dict, List
try:
    from typing import TYPE_CHECKING
except ImportError:
    TYPE_CHECKING = False

if TYPE_CHECKING:
    pass

from .patterns import PATTERNS
try:
    from .validators import validate_match as _validate_match
except ImportError:
    def _validate_match(pattern_name, match):
        return True

_SCAN_FLAGS = re.MULTILINE | re.IGNORECASE
# Compiled once at import instead of re-compiling built-in patterns for every
# file. Custom patterns are compiled on demand because their definitions are
# not known until config is loaded.
_COMPILED_PATTERNS = {name: re.compile(p, _SCAN_FLAGS) for name, p in PATTERNS.items()}

# File extensions to skip for performance and accuracy
SKIP_EXTENSIONS = {
    '.pyc', '.pyo', '.pyd', '.so', '.dll', '.exe', '.bin', '.jpg', '.jpeg',
    '.png', '.gif', '.bmp', '.ico', '.svg', '.pdf', '.zip', '.tar', '.gz',
    '.rar', '.7z', '.mp3', '.mp4', '.avi', '.mov', '.wmv', '.flv', '.woff',
    '.woff2', '.ttf', '.eot', '.otf'
}

# Directories to skip
SKIP_DIRS = {
    '__pycache__', '.git', '.svn', '.hg', '.bzr', 'node_modules', '.venv',
    'venv', 'env', '.env', 'build', 'dist', '.pytest_cache', '.tox',
    '.coverage', '.mypy_cache', '.DS_Store', 'Thumbs.db'
}


def should_skip_file(filepath: Path) -> bool:
    """Check if file should be skipped based on extension or size."""
    if filepath.suffix.lower() in SKIP_EXTENSIONS:
        return True

    try:
        if filepath.stat().st_size > 10 * 1024 * 1024:
            return True
    except OSError:
        return True

    return False


def should_skip_directory(dirpath: Path) -> bool:
    """Check if directory should be skipped."""
    return dirpath.name in SKIP_DIRS


def _extract_notebook_content(filepath):
    # type: (str) -> str
    """Extract source text from all cells of a Jupyter notebook."""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            nb = json.load(f)
    except (OSError, IOError, PermissionError, ValueError, TypeError):
        return ''

    parts = []
    for cell in nb.get('cells', []):
        if not isinstance(cell, dict):
            continue
        src = cell.get('source', [])
        if isinstance(src, list):
            parts.append(''.join(str(part) for part in src))
        elif isinstance(src, str):
            parts.append(src)
    return '\n'.join(parts)


def _full_matches(name, pattern, content):
    # type: (str, str, str) -> List[str]
    """Return complete regex matches, never capture-group tuples.

    ``re.findall`` changes its return type when a pattern contains capture
    groups: one group returns only the captured text and multiple groups
    return tuples. That made the scanner's evidence model pattern-dependent
    and could pass tuples into validators that require strings. ``finditer``
    keeps the contract stable: every finding is the full matched substring.
    """
    compiled = _COMPILED_PATTERNS.get(name) if PATTERNS.get(name) == pattern else None
    if compiled is None:
        compiled = re.compile(pattern, _SCAN_FLAGS)
    return [match.group(0) for match in compiled.finditer(content) if match.group(0)]


def scan_file(filepath: str, extra_patterns: Dict[str, str] = None) -> Dict[str, List[str]]:
    """
    Scan a single file for secret patterns.

    Args:
        filepath: Path to the file to scan
        extra_patterns: Additional {name: regex} patterns to scan alongside
            PATTERNS (e.g. opt-in PII patterns, user-defined custom_patterns)

    Returns:
        Dictionary with pattern names as keys and complete matched strings as
        values. Unexpected validator/runtime failures are deliberately not
        swallowed: callers such as the CLI must distinguish a scanner error
        from a genuinely clean file.
    """
    findings = {}
    path_obj = Path(filepath)

    if should_skip_file(path_obj):
        return findings

    content = None

    if path_obj.suffix.lower() == '.ipynb':
        content = _extract_notebook_content(filepath)
        if not content:
            return findings
    else:
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                with open(filepath, "r", encoding=encoding) as f:
                    content = f.read()
                break
            except UnicodeDecodeError:
                continue
            except (OSError, IOError, PermissionError):
                return findings

    if content is None:
        return findings

    active_patterns = PATTERNS if not extra_patterns else {**PATTERNS, **extra_patterns}
    for name, pattern in active_patterns.items():
        try:
            matches = _full_matches(name, pattern, content)
        except re.error:
            # User-defined invalid regexes are ignored here for backwards
            # compatibility. Config validation can reject them separately.
            continue

        if not matches:
            continue

        # Remove duplicates while preserving order, then validate the full
        # matched substring. Validators now always receive ``str``.
        unique_matches = list(dict.fromkeys(matches))
        validated = [m for m in unique_matches if _validate_match(name, m)]
        if validated:
            findings[name] = validated

    return findings


def scan_directory(directory: str, extra_patterns: Dict[str, str] = None) -> Dict[str, Dict[str, List[str]]]:
    """
    Scan a directory recursively for secret patterns.

    Args:
        directory: Path to the directory to scan
        extra_patterns: Additional {name: regex} patterns to scan alongside
            PATTERNS (e.g. opt-in PII patterns, user-defined custom_patterns)

    Returns:
        Dictionary with file paths as keys and findings as values
    """
    results = {}
    directory_path = Path(directory)

    if not directory_path.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")

    if not directory_path.is_dir():
        file_findings = scan_file(str(directory_path), extra_patterns=extra_patterns)
        if file_findings:
            results[str(directory_path)] = file_findings
        return results

    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not should_skip_directory(Path(d))]

        for file in files:
            file_path = root_path / file

            if should_skip_file(file_path):
                continue

            file_findings = scan_file(str(file_path), extra_patterns=extra_patterns)
            if file_findings:
                try:
                    rel_path = file_path.relative_to(directory_path)
                    results[str(rel_path)] = file_findings
                except ValueError:
                    results[str(file_path)] = file_findings

    return results


def get_scan_stats(results: Dict[str, Dict[str, List[str]]]) -> Dict[str, int]:
    """Get statistics about the scan results."""
    total_files = len(results)
    total_secrets = sum(len(findings) for findings in results.values())
    total_matches = sum(
        len(matches) for findings in results.values()
        for matches in findings.values()
    )

    pattern_counts = {}
    for findings in results.values():
        for pattern_name, matches in findings.items():
            pattern_counts[pattern_name] = pattern_counts.get(pattern_name, 0) + len(matches)

    return {
        'total_files': total_files,
        'total_secret_types': total_secrets,
        'total_matches': total_matches,
        'pattern_breakdown': pattern_counts
    }
