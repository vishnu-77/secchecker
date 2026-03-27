"""Entropy-based secret detection using Shannon entropy analysis."""
import re
import math
import os
from pathlib import Path
from typing import Any, Dict, List

BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
HEX_CHARS = '0123456789abcdefABCDEF'

SKIP_EXTENSIONS = {'.min.js', '.min.css', '.html', '.htm', '.svg',
                   '.lock', '.sum', '.mod', '.pyc', '.pyo'}

# Matches security-named variables assigned string values
ASSIGNMENT_PATTERN = re.compile(
    r'(?i)(?:password|secret|key|token|credential|api|auth|access|private|cert|seed)'
    r'\s*(?:=|:)\s*["\']([A-Za-z0-9+/=_\-]{20,200})["\']'
)

PLACEHOLDER_WORDS = ('example', 'placeholder', 'changeme', 'yourkey', 'your_', 'insert', 'replace')


def shannon_entropy(data, charset):
    # type: (str, str) -> float
    """Calculate Shannon entropy of data filtered to charset characters."""
    filtered = [c for c in data if c in charset]
    if len(filtered) < 8:
        return 0.0
    freq = {}
    for c in filtered:
        freq[c] = freq.get(c, 0) + 1
    total = float(len(filtered))
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log(p, 2)
    return entropy


def _is_likely_secret_value(value):
    # type: (str) -> bool
    """Return False for values that are likely placeholders or non-secrets."""
    if value.startswith(('http://', 'https://', 'ftp://')):
        return False
    if '/' in value and value.count('/') > 2:
        return False
    lower = value.lower()
    return not any(p in lower for p in PLACEHOLDER_WORDS)


def get_high_entropy_strings(content, min_len=20, max_len=200, threshold=4.5):
    # type: (str, int, int, float) -> List[Dict[str, Any]]
    """Scan content for high-entropy strings in assignment context."""
    results = []
    seen = set()

    for line_num, line in enumerate(content.splitlines(), 1):
        for m in ASSIGNMENT_PATTERN.finditer(line):
            value = m.group(1)
            if len(value) < min_len or len(value) > max_len:
                continue
            if value in seen:
                continue
            if not _is_likely_secret_value(value):
                continue

            b64 = shannon_entropy(value, BASE64_CHARS)
            hex_e = shannon_entropy(value, HEX_CHARS)
            best = max(b64, hex_e)

            if best >= threshold:
                seen.add(value)
                results.append({
                    'value': value[:50] + ('...' if len(value) > 50 else ''),
                    'entropy': round(best, 2),
                    'charset': 'base64' if b64 >= hex_e else 'hex',
                    'line_number': line_num,
                    'context': line.strip()[:100],
                })

    return results


def scan_file_entropy(filepath, threshold=4.5, min_len=20):
    # type: (str, float, int) -> Dict[str, List[str]]
    """Scan a file for high-entropy strings. Returns scan_file()-compatible dict."""
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return {}

    ext = path.suffix.lower()
    if ext in SKIP_EXTENSIONS or '.min.' in path.name.lower():
        return {}

    try:
        if path.stat().st_size > 10 * 1024 * 1024:
            return {}
    except OSError:
        return {}

    content = None
    for encoding in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                content = f.read()
            break
        except (UnicodeDecodeError, IOError):
            continue

    if not content:
        return {}

    hits = get_high_entropy_strings(content, min_len=min_len, threshold=threshold)
    if not hits:
        return {}

    matches = [
        "entropy={} charset={} line={}: {}".format(
            h['entropy'], h['charset'], h['line_number'], h['value']
        )
        for h in hits
    ]
    return {"High Entropy String": matches}
