import pytest
import os
from secchecker.config import (
    get_default_config, find_config_file, load_config, _parse_simple_yaml,
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


def test_find_config_file_not_found(tmp_path):
    assert find_config_file(scan_root=str(tmp_path)) is None


def test_parse_scalars():
    result = _parse_simple_yaml('severity_threshold: HIGH\nversion: 1\nenabled: true\n')
    assert result['severity_threshold'] == 'HIGH'
    assert result['version'] == 1
    assert result['enabled'] is True


def test_invalid_severity_uses_default(tmp_path):
    cfg = tmp_path / '.secchecker.yml'
    cfg.write_text('severity_threshold: INVALID\n')
    config = load_config(config_path=str(cfg))
    assert config['severity_threshold'] is None
