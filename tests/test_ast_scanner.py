"""Tests for secchecker.ast_scanner AST-based Python scanner."""
import warnings

import pytest
from secchecker.ast_scanner import scan_file_ast, scan_directory_ast


def _write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return str(f)


# ---------------------------------------------------------------------------
# Hardcoded secret assignments
# ---------------------------------------------------------------------------

def test_hardcoded_password_assignment(tmp_path):
    src = 'password = "supersecretpassword"\n'
    path = _write(tmp_path, "config.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" in findings


def test_hardcoded_api_key_assignment(tmp_path):
    src = 'api_key = "sk-abcdefghij1234567890abcdefghij12"\n'
    path = _write(tmp_path, "app.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" in findings


def test_short_value_not_reported(tmp_path):
    # Values shorter than _MIN_SECRET_LEN (8) should not be reported
    src = 'password = "hi"\n'
    path = _write(tmp_path, "short.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" not in findings


def test_non_sensitive_name_not_reported(tmp_path):
    src = 'username = "alice_longname_here"\n'
    path = _write(tmp_path, "user.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" not in findings


# ---------------------------------------------------------------------------
# eval / exec detection
# ---------------------------------------------------------------------------

def test_eval_call_detected(tmp_path):
    src = 'result = eval(user_code)\n'
    path = _write(tmp_path, "danger.py", src)
    findings = scan_file_ast(path)
    assert "AST - eval/exec Call" in findings


def test_exec_call_detected(tmp_path):
    src = 'exec(script_content)\n'
    path = _write(tmp_path, "run.py", src)
    findings = scan_file_ast(path)
    assert "AST - eval/exec Call" in findings


def test_eval_with_string_literal(tmp_path):
    src = 'x = eval("1 + 1")\n'
    path = _write(tmp_path, "const_eval.py", src)
    findings = scan_file_ast(path)
    assert "AST - eval/exec Call" in findings


# ---------------------------------------------------------------------------
# Taint tracking
# ---------------------------------------------------------------------------

def test_taint_from_os_environ_to_eval(tmp_path):
    src = (
        "import os\n"
        "user_input = os.getenv('CMD')\n"
        "eval(user_input)\n"
    )
    path = _write(tmp_path, "taint.py", src)
    findings = scan_file_ast(path)
    # eval itself is flagged
    assert "AST - eval/exec Call" in findings


# ---------------------------------------------------------------------------
# Non-.py files are skipped
# ---------------------------------------------------------------------------

def test_non_python_file_skipped(tmp_path):
    src = 'password = "supersecretpassword"\n'
    path = _write(tmp_path, "config.js", src)
    findings = scan_file_ast(path)
    assert findings == {}


# ---------------------------------------------------------------------------
# Syntax error handled gracefully
# ---------------------------------------------------------------------------

def test_syntax_error_returns_empty(tmp_path):
    src = "def broken(\n"
    path = _write(tmp_path, "broken.py", src)
    findings = scan_file_ast(path)
    assert isinstance(findings, dict)


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

def test_scan_directory_finds_secrets(tmp_path):
    _write(tmp_path, "a.py", 'secret_key = "MyS3cretK3y!"\n')
    _write(tmp_path, "b.py", 'x = 1\n')
    results = scan_directory_ast(str(tmp_path))
    assert len(results) >= 1
    found = any("AST - Hardcoded Secret Assignment" in v for v in results.values())
    assert found


def test_scan_directory_skips_non_py(tmp_path):
    _write(tmp_path, "config.js", 'password = "supersecret"\n')
    _write(tmp_path, "readme.md", 'password = "supersecret"\n')
    results = scan_directory_ast(str(tmp_path))
    assert results == {}


# ---------------------------------------------------------------------------
# Regression: G-1 — ast.Constant.s is removed in Python 3.14 and deprecated
# on 3.12/3.13. _get_string_value must use node.value, never node.s.
# ---------------------------------------------------------------------------

def test_regression_g1_no_deprecated_constant_attrs(tmp_path):
    src = (
        'password = "supersecretpassword"\n'
        'count = 42\n'
        'other = do_thing()\n'
        'result = eval("1+1")\n'
    )
    path = _write(tmp_path, "g1.py", src)
    with warnings.catch_warnings():
        warnings.simplefilter("error", DeprecationWarning)
        findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" in findings
    assert "AST - eval/exec Call" in findings
