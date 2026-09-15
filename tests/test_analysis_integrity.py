"""Cross-cutting regressions for fail-visible analysis and AI scan wiring."""
import pytest

from secchecker.cli import _run_scan
from secchecker.config import ConfigError, load_config


def test_strict_config_missing_explicit_file_fails_closed(tmp_path):
    missing = tmp_path / "missing.yml"
    with pytest.raises(ConfigError, match="not found"):
        load_config(config_path=str(missing), strict=True)


def test_strict_config_rejects_malformed_syntax(tmp_path):
    cfg = tmp_path / ".secchecker.yml"
    cfg.write_text("{{invalid: yaml: content:::", encoding="utf-8")
    with pytest.raises(ConfigError, match="Unsupported configuration syntax"):
        load_config(config_path=str(cfg), strict=True)


def test_strict_config_rejects_invalid_severity(tmp_path):
    cfg = tmp_path / ".secchecker.yml"
    cfg.write_text("severity_threshold: BANANA\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="severity_threshold"):
        load_config(config_path=str(cfg), strict=True)


def test_strict_config_rejects_invalid_custom_regex(tmp_path):
    cfg = tmp_path / ".secchecker.yml"
    cfg.write_text(
        'custom_patterns:\n  "Broken": "([unterminated"\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="Invalid custom pattern"):
        load_config(config_path=str(cfg), strict=True)


def test_llm_scan_includes_contextual_python_ast_analysis(tmp_path):
    """The recommended AI scan must reach provider credential AST checks."""
    src = tmp_path / "provider.py"
    src.write_text(
        "from openai import OpenAI\n"
        "openai_api_key = 'hardcoded-provider-credential'\n"
        "client = OpenAI(api_key=openai_api_key)\n",
        encoding="utf-8",
    )

    results = _run_scan(str(src), "llm", True, {})
    findings = results[str(src)]

    assert "AST - Hardcoded AI Credential Used in Provider Client" in findings
