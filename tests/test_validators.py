"""Tests for secchecker.validators post-match validation."""
import pytest
from secchecker.validators import luhn_check, is_valid_jwt, validate_match, has_sufficient_entropy


# ---------------------------------------------------------------------------
# luhn_check
# ---------------------------------------------------------------------------

def test_luhn_valid_visa():
    assert luhn_check("4532015112830366") is True


def test_luhn_valid_mastercard():
    assert luhn_check("5425233430109903") is True


def test_luhn_invalid():
    assert luhn_check("1234567890123456") is False


def test_luhn_strips_spaces():
    assert luhn_check("4532 0151 1283 0366") is True


def test_luhn_empty():
    assert luhn_check("") is False


# ---------------------------------------------------------------------------
# is_valid_jwt
# ---------------------------------------------------------------------------

_VALID_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ"
    ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
)


def test_jwt_valid():
    assert is_valid_jwt(_VALID_JWT) is True


def test_jwt_two_parts_invalid():
    assert is_valid_jwt("header.payload") is False


def test_jwt_bad_base64_invalid():
    assert is_valid_jwt("not_base64!.not_base64!.sig") is False


def test_jwt_no_alg_field():
    import base64, json
    header = base64.urlsafe_b64encode(json.dumps({"typ": "JWT"}).encode()).rstrip(b"=").decode()
    payload = base64.urlsafe_b64encode(json.dumps({"sub": "123"}).encode()).rstrip(b"=").decode()
    assert is_valid_jwt("{}.{}.sig".format(header, payload)) is False


# ---------------------------------------------------------------------------
# has_sufficient_entropy
# ---------------------------------------------------------------------------

def test_entropy_high_random():
    assert has_sufficient_entropy("aB3$kP9mZ2xQ") is True


def test_entropy_low_repeated():
    assert has_sufficient_entropy("aaaaaaaaaa") is False


# ---------------------------------------------------------------------------
# validate_match dispatcher
# ---------------------------------------------------------------------------

def test_validate_credit_card_valid():
    assert validate_match("Credit Card", "4532015112830366") is True


def test_validate_credit_card_invalid_luhn():
    assert validate_match("Credit Card", "1234567890123456") is False


def test_validate_jwt_valid():
    assert validate_match("JWT Token", _VALID_JWT) is True


def test_validate_jwt_invalid():
    assert validate_match("JWT Token", "not.a.jwt") is False


def test_validate_placeholder_suppressed():
    assert validate_match("AWS Access Key", "EXAMPLE_KEY_HERE") is False


def test_validate_fake_prefix_suppressed():
    assert validate_match("GitHub Token", "TEST_TOKEN_PLACEHOLDER") is False


def test_validate_unknown_pattern_passes():
    # Unknown pattern with non-placeholder value should pass
    assert validate_match("Some Custom Pattern", "RealLooking$ecret99!") is True


def test_validate_repeated_chars_suppressed():
    # Value with < 3 unique chars after stripping dashes/underscores
    assert validate_match("AWS Access Key", "aaaaaaaaaaaaaaaa") is False
