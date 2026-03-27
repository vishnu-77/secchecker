"""Post-match validators for secchecker.

Each validator takes a raw regex match string and returns True if the
match is likely a real finding, False if it should be discarded.

validate_match(pattern_name, match) is the single dispatch entry point.
"""
import re
import base64
import json
import math
from typing import Optional


# ---------------------------------------------------------------------------
# Luhn algorithm — credit card validator
# ---------------------------------------------------------------------------

def luhn_check(number):
    # type: (str) -> bool
    """Return True if *number* (digits only) passes the Luhn check."""
    digits = re.sub(r'\D', '', number)
    if not digits:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


# ---------------------------------------------------------------------------
# JWT structure validator
# ---------------------------------------------------------------------------

def _b64url_decode(segment):
    # type: (str) -> Optional[bytes]
    """Decode a base64url segment without raising on failure."""
    # Pad to a multiple of 4
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment = segment + '=' * padding
    try:
        return base64.urlsafe_b64decode(segment)
    except Exception:
        return None


def is_valid_jwt(token):
    # type: (str) -> bool
    """Return True if *token* has valid JWT structure (header.payload.signature)."""
    parts = token.split('.')
    if len(parts) != 3:
        return False
    header_bytes = _b64url_decode(parts[0])
    if header_bytes is None:
        return False
    payload_bytes = _b64url_decode(parts[1])
    if payload_bytes is None:
        return False
    # Header and payload must be valid JSON objects
    try:
        header = json.loads(header_bytes.decode('utf-8'))
        payload = json.loads(payload_bytes.decode('utf-8'))
    except (ValueError, UnicodeDecodeError):
        return False
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return False
    # A real JWT header always has an "alg" field
    if 'alg' not in header:
        return False
    # Signature segment must be non-empty
    return len(parts[2]) > 0


# ---------------------------------------------------------------------------
# Entropy confirmation — catches known-bad test/placeholder values
# ---------------------------------------------------------------------------

_LOW_ENTROPY_PLACEHOLDERS = re.compile(
    r'(?i)(example|test|fake|dummy|placeholder|your[_\-]?key|insert[_\-]?here'
    r'|changeme|replace|sample|todo|xxx+|aaa+|000+|secret[_\-]?here)',
    re.IGNORECASE
)


def _shannon_entropy(s):
    # type: (str) -> float
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = float(len(s))
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def has_sufficient_entropy(value, threshold=3.0):
    # type: (str, float) -> bool
    """Return True if *value* has Shannon entropy above *threshold*."""
    return _shannon_entropy(value) >= threshold


# ---------------------------------------------------------------------------
# False-positive context patterns
# ---------------------------------------------------------------------------

_FP_CONTEXT = re.compile(
    r'(?i)(TEST_|EXAMPLE_|FAKE_|DUMMY_|PLACEHOLDER_|SAMPLE_)',
)


def _looks_like_placeholder(value):
    # type: (str) -> bool
    """Return True if the matched value looks like a well-known placeholder."""
    if _LOW_ENTROPY_PLACEHOLDERS.search(value):
        return True
    if _FP_CONTEXT.search(value):
        return True
    # Repeating character patterns: AAAA..., 1234..., etc.
    if len(set(value.replace('-', '').replace('_', ''))) < 3:
        return True
    return False


# ---------------------------------------------------------------------------
# Public dispatch
# ---------------------------------------------------------------------------

def validate_match(pattern_name, match):
    # type: (str, str) -> bool
    """Return True if *match* is a likely real finding for *pattern_name*.

    Returns False to suppress the match (i.e. treat it as a false positive).
    """
    # Universal placeholder filter
    if _looks_like_placeholder(match):
        return False

    name_lower = pattern_name.lower()

    # Credit card — apply Luhn check
    if 'credit card' in name_lower:
        return luhn_check(match)

    # JWT — apply structural check
    if 'jwt' in name_lower or 'bearer' in name_lower:
        return is_valid_jwt(match)

    # Default: accept the match.
    # Entropy filtering is available via has_sufficient_entropy() for callers
    # that know the captured value is a full secret (not a keyword group).
    return True
