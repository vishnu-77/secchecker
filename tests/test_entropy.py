import os

import pytest
from secchecker.entropy import (
    shannon_entropy, get_high_entropy_strings, scan_file_entropy,
    scan_directory_entropy, BASE64_CHARS, HEX_CHARS,
)


def test_high_entropy_base64():
    value = "aB3cD4eF5gH6iJ7kL8mN9oP0qR1sT2uV"
    assert shannon_entropy(value, BASE64_CHARS) > 4.0


def test_low_entropy_word():
    assert shannon_entropy("password", BASE64_CHARS) < 3.5


def test_repeated_chars_low_entropy():
    assert shannon_entropy("aaaaaaaaaaaaaaaa", BASE64_CHARS) < 0.1


def test_get_high_entropy_finds_secret():
    content = 'SECRET_KEY = "aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab"'
    hits = get_high_entropy_strings(content, min_len=20, threshold=4.0)
    assert len(hits) >= 1
    assert hits[0]['entropy'] > 4.0


def test_get_high_entropy_skips_placeholder():
    content = 'API_KEY = "your_api_key_here_placeholder"'
    hits = get_high_entropy_strings(content, min_len=20, threshold=4.0)
    assert len(hits) == 0


def test_scan_file_entropy_detects_secret(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('db_password = "xK9mP2nQ8rL5vJ3wY7tB4cZ1aE6hF0iG"')
    result = scan_file_entropy(str(f))
    assert "High Entropy String" in result
    assert len(result["High Entropy String"]) >= 1


def test_scan_file_entropy_nonexistent():
    assert scan_file_entropy("nonexistent_xyz.py") == {}


def test_scan_file_entropy_skips_minjs(tmp_path):
    f = tmp_path / "bundle.min.js"
    f.write_text('var x="aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890ab";')
    assert scan_file_entropy(str(f)) == {}


def test_entropy_threshold_respected(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('key = "passwordpasswordpassword123"')
    result = scan_file_entropy(str(f), threshold=4.9)
    assert result == {} or "High Entropy String" not in result


# ---------------------------------------------------------------------------
# Regression: Q-3 — the entropy directory walk keyed results by absolute
# path while regex/AST scanners key by path relative to the scan root, so
# the same file appeared under two different keys and skip filters were
# never applied to the entropy walk.
# ---------------------------------------------------------------------------

def test_regression_q3_entropy_keys_are_relative(tmp_path):
    sub = tmp_path / "sub"
    sub.mkdir()
    (sub / "app.py").write_text('db_password = "xK9mP2nQ8rL5vJ3wY7tB4cZ1aE6hF0iG"')

    results = scan_directory_entropy(str(tmp_path))

    assert results, "expected at least one high-entropy finding"
    for key in results:
        assert not os.path.isabs(key)
        assert not key.startswith(str(tmp_path))
    assert any("High Entropy String" in v for v in results.values())


def test_regression_q3_entropy_respects_skip_dirs(tmp_path):
    skip_dir = tmp_path / "node_modules"
    skip_dir.mkdir()
    (skip_dir / "bundle.py").write_text('db_password = "xK9mP2nQ8rL5vJ3wY7tB4cZ1aE6hF0iG"')

    results = scan_directory_entropy(str(tmp_path))

    assert not any("node_modules" in key for key in results)


def test_regression_q3_entropy_threshold_from_config(tmp_path):
    (tmp_path / "config.py").write_text('key = "passwordpasswordpassword123"')

    results = scan_directory_entropy(str(tmp_path), threshold=7.9)

    assert results == {}


def test_regression_q3_entropy_merges_with_regex_scanner(tmp_path):
    from secchecker.cli import _run_scan

    f = tmp_path / "config.py"
    f.write_text(
        'password="hunter2secret"\n'
        'db_password = "xK9mP2nQ8rL5vJ3wY7tB4cZ1aE6hF0iG"\n'
    )
    config = {"entropy": {"enabled": True}}

    results = _run_scan(str(tmp_path), "secrets", False, config)

    matching_keys = [k for k in results if "config.py" in k]
    assert len(matching_keys) == 1
    key = matching_keys[0]
    assert "High Entropy String" in results[key]
    assert "Password in Config" in results[key]
