import pytest
import os
from secchecker.config import (
    get_default_config, find_config_file, load_config, _parse_simple_yaml,
    is_path_excluded, is_pattern_excluded,
)


def test_default_config_structure():
    config = get_default_config()
    assert isinstance(config['exclude_paths'], list)
    assert isinstance(config['exclude_patterns'], list)
    assert isinstance(config['custom_patterns'], dict)
    assert isinstance(config['scan_types'], list)
    assert isinstance(config['entropy'], dict)
    assert config['entropy']['enabled'] is False
    assert config['entropy']['threshold'] == 4.5


def test_load_config_no_file():
    config = load_config(config_path='/nonexistent/.secchecker.yml')
    assert config == get_default_config()


def test_load_config_from_file(tmp_path):
    cfg = tmp_path / '.secchecker.yml'
    cfg.write_text(
        'version: 1\n'
        'severity_threshold: HIGH\n'
        'exclude_paths:\n'
        '  - "tests/"\n'
        '  - "*.mock.*"\n'
        'scan_types:\n'
        '  - secrets\n'
        '  - llm\n'
        'entropy:\n'
        '  enabled: true\n'
        '  threshold: 4.5\n'
    )
    config = load_config(config_path=str(cfg))
    assert config['severity_threshold'] == 'HIGH'
    assert 'tests/' in config['exclude_paths']
    assert 'secrets' in config['scan_types']
    assert 'llm' in config['scan_types']
    assert config['entropy']['enabled'] is True


def test_load_config_custom_patterns(tmp_path):
    cfg = tmp_path / '.secchecker.yml'
    cfg.write_text('custom_patterns:\n  "My Token": "myco_[a-zA-Z0-9]{32}"\n')
    config = load_config(config_path=str(cfg))
    assert 'My Token' in config['custom_patterns']
    assert config['custom_patterns']['My Token'] == 'myco_[a-zA-Z0-9]{32}'


def test_load_config_invalid_returns_defaults(tmp_path):
    cfg = tmp_path / '.secchecker.yml'
    cfg.write_text('{{invalid: yaml: content:::')
    config = load_config(config_path=str(cfg))
    assert config == get_default_config()


def test_find_config_file(tmp_path):
    cfg = tmp_path / '.secchecker.yml'
    cfg.write_text('version: 1\n')
    found = find_config_file(scan_root=str(tmp_path))
    assert found is not None
    assert found.endswith('.secchecker.yml')


def test_find_config_file_not_found(tmp_path, monkeypatch):
    # chdir into the empty tmp dir so the cwd fallback can't pick up a
    # .secchecker.yml that happens to exist in the project root.
    monkeypatch.chdir(tmp_path)
    assert find_config_file(scan_root=str(tmp_path)) is None


def test_parse_scalars():
    result = _parse_simple_yaml('severity_threshold: HIGH\nversion: 1\nenabled: true\n')
    assert result['severity_threshold'] == 'HIGH'
    assert result['version'] == 1
    assert result['enabled'] is True


def test_parse_strips_inline_comments():
    # Inline comments on quoted list items and scalars must not leak into values.
    text = (
        'exclude_paths:\n'
        '  - "demo/"        # intentional demo\n'
        '  - tests/         # fixtures\n'
        'severity_threshold: HIGH   # only high and above\n'
    )
    result = _parse_simple_yaml(text)
    assert result['exclude_paths'] == ['demo/', 'tests/']
    assert result['severity_threshold'] == 'HIGH'


def test_parse_skips_comment_lines_between_list_items():
    # Full-line comments interspersed between list items must not truncate it.
    text = (
        'exclude_paths:\n'
        '  # first\n'
        '  - "demo/"\n'
        '  # second\n'
        '  - "tests/"\n'
        '  - "sample-reports/"\n'
    )
    result = _parse_simple_yaml(text)
    assert result['exclude_paths'] == ['demo/', 'tests/', 'sample-reports/']


def test_invalid_severity_uses_default(tmp_path):
    cfg = tmp_path / '.secchecker.yml'
    cfg.write_text('severity_threshold: INVALID\n')
    config = load_config(config_path=str(cfg))
    assert config['severity_threshold'] is None


# ---------------------------------------------------------------------------
# is_path_excluded — exclude_paths matching
# ---------------------------------------------------------------------------

def test_exclude_none_or_empty():
    assert is_path_excluded('secchecker/cli.py', None) is False
    assert is_path_excluded('secchecker/cli.py', []) is False


def test_exclude_dir_prefix():
    ex = ['tests/']
    assert is_path_excluded('tests/test_cli.py', ex) is True
    assert is_path_excluded('secchecker/cli.py', ex) is False


def test_exclude_component_anywhere():
    ex = ['node_modules']
    assert is_path_excluded('frontend/node_modules/lib/x.js', ex) is True
    assert is_path_excluded('node_modules/x.js', ex) is True
    assert is_path_excluded('src/nodes/x.js', ex) is False  # partial name, no match


def test_exclude_glob_basename_and_path():
    ex = ['*.mock.*']
    assert is_path_excluded('src/config.mock.js', ex) is True
    assert is_path_excluded('config.mock.ts', ex) is True
    assert is_path_excluded('src/config.js', ex) is False


def test_exclude_multi_segment_literal():
    ex = ['secchecker/patterns.py']
    assert is_path_excluded('secchecker/patterns.py', ex) is True
    assert is_path_excluded('secchecker/llm_patterns.py', ex) is False


def test_exclude_windows_separators_normalized():
    ex = ['demo/']
    assert is_path_excluded('demo\\app.py', ex) is True


def test_run_scan_respects_exclude_paths(tmp_path):
    from secchecker.cli import _run_scan
    (tmp_path / 'keep.py').write_text('password = "hunter2secret"\n')
    demo = tmp_path / 'demo'
    demo.mkdir()
    (demo / 'vuln.py').write_text('password = "hunter2secret"\n')

    no_ex = _run_scan(str(tmp_path), 'secrets', True, {})
    with_ex = _run_scan(str(tmp_path), 'secrets', True, {'exclude_paths': ['demo/']})

    joined_no_ex = '||'.join(no_ex.keys()).replace('\\', '/')
    joined_with_ex = '||'.join(with_ex.keys()).replace('\\', '/')
    assert 'demo/vuln.py' in joined_no_ex
    assert 'demo/vuln.py' not in joined_with_ex
    assert 'keep.py' in joined_with_ex


# ---------------------------------------------------------------------------
# is_pattern_excluded — exclude_patterns (finding-category) matching
# ---------------------------------------------------------------------------

def test_is_pattern_excluded_globs():
    assert is_pattern_excluded('Email', None) is False
    assert is_pattern_excluded('Email', []) is False
    assert is_pattern_excluded('Email', ['Email']) is True
    assert is_pattern_excluded('email', ['Email']) is True  # case-insensitive
    assert is_pattern_excluded('LLM - Hardcoded Jailbreak Instruction', ['LLM - *']) is True
    assert is_pattern_excluded('Password in Config', ['LLM - *']) is False


# ---------------------------------------------------------------------------
# Regression: G-3 — exclude_patterns, custom_patterns, and scan_types were
# parsed from .secchecker.yml but never consumed anywhere.
# ---------------------------------------------------------------------------

def test_regression_g3_exclude_patterns_drops_category(tmp_path):
    from secchecker.cli import _run_scan
    # "key" matches the regex-based "Generic Secret" pattern but is not a
    # sensitive AST assignment name, so this fixture yields exactly one
    # finding category to isolate the exclude_patterns behavior.
    (tmp_path / 'app.py').write_text('key = "abcdefghijklmnopqrstuvwxyz123456"\n')

    no_ex = _run_scan(str(tmp_path), 'secrets', True, {})
    with_ex = _run_scan(str(tmp_path), 'secrets', True,
                         {'exclude_patterns': ['Generic Secret']})

    assert any('Generic Secret' in v for v in no_ex.values())
    assert not any('Generic Secret' in v for v in with_ex.values())


def test_regression_g3_custom_patterns_scanned(tmp_path):
    from secchecker.cli import _run_scan
    (tmp_path / 'app.py').write_text('token = "myco_abcdefghij1234567890abcdefghij12"\n')

    config = {'custom_patterns': {'My Token': 'myco_[a-zA-Z0-9]{32}'}}
    results = _run_scan(str(tmp_path), 'secrets', True, config,
                         extra_patterns=config['custom_patterns'])

    assert any('My Token' in v for v in results.values())


def test_regression_g3_scan_types_resolution():
    from secchecker.cli import _resolve_scan_types
    assert _resolve_scan_types(None, {'scan_types': ['llm']}) == {'llm'}
    assert _resolve_scan_types('secrets', {'scan_types': ['llm']}) == {'secrets'}
    assert _resolve_scan_types(None, {}) == {'secrets'}
    assert _resolve_scan_types(None, {'scan_types': ['secrets', 'llm']}) == {'secrets', 'llm'}


def test_regression_g3_run_scan_accepts_type_set(tmp_path):
    from secchecker.cli import _run_scan
    (tmp_path / 'app.py').write_text(
        'password = "hunter2secret"\n'
        'prompt = "You are a helpful assistant. " + user_input\n'
    )
    results = _run_scan(str(tmp_path), {'secrets', 'llm'}, True, {})
    all_categories = set()
    for findings in results.values():
        all_categories.update(findings.keys())
    assert 'Password in Config' in all_categories
