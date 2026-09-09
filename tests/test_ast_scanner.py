"""Tests for secchecker.ast_scanner AST-based Python scanner."""
import warnings

import pytest
from secchecker.ast_scanner import scan_file_ast, scan_directory_ast


def _write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return str(f)


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
    src = 'password = "hi"\n'
    path = _write(tmp_path, "short.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" not in findings


def test_non_sensitive_name_not_reported(tmp_path):
    src = 'username = "alice_longname_here"\n'
    path = _write(tmp_path, "user.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded Secret Assignment" not in findings


def test_hardcoded_ai_credential_variable_used_in_openai_client(tmp_path):
    src = (
        'from openai import OpenAI\n'
        'openai_api_key = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890"\n'
        'client = OpenAI(api_key=openai_api_key)\n'
    )
    path = _write(tmp_path, "provider.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded AI Credential Used in Provider Client" in findings


def test_literal_ai_credential_used_in_anthropic_client(tmp_path):
    src = (
        'from anthropic import Anthropic\n'
        'client = Anthropic(api_key="sk-ant-this-is-a-hardcoded-provider-secret")\n'
    )
    path = _write(tmp_path, "provider_literal.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded AI Credential Used in Provider Client" in findings


def test_environment_ai_credential_not_reported_as_hardcoded_provider_use(tmp_path):
    src = (
        'import os\n'
        'from openai import OpenAI\n'
        'openai_api_key = os.getenv("OPENAI_API_KEY")\n'
        'client = OpenAI(api_key=openai_api_key)\n'
    )
    path = _write(tmp_path, "provider_env.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded AI Credential Used in Provider Client" not in findings


def test_unrelated_api_key_argument_not_treated_as_ai_provider(tmp_path):
    src = (
        'api_key = "this-is-hardcoded-but-not-an-ai-provider"\n'
        'client = InternalService(api_key=api_key)\n'
    )
    path = _write(tmp_path, "internal.py", src)
    findings = scan_file_ast(path)
    assert "AST - Hardcoded AI Credential Used in Provider Client" not in findings


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


def test_taint_from_os_environ_to_eval(tmp_path):
    src = (
        "import os\n"
        "user_input = os.getenv('CMD')\n"
        "eval(user_input)\n"
    )
    path = _write(tmp_path, "taint.py", src)
    findings = scan_file_ast(path)
    assert "AST - eval/exec Call" in findings


def test_non_python_file_skipped(tmp_path):
    src = 'password = "supersecretpassword"\n'
    path = _write(tmp_path, "config.js", src)
    findings = scan_file_ast(path)
    assert findings == {}


def test_syntax_error_returns_empty(tmp_path):
    src = "def broken(\n"
    path = _write(tmp_path, "broken.py", src)
    findings = scan_file_ast(path)
    assert isinstance(findings, dict)


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
