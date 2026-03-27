"""Config file loader for secchecker — parses .secchecker.yml using stdlib only."""
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_FILENAME = '.secchecker.yml'
VALID_SCAN_TYPES = {'secrets', 'llm', 'devsecops', 'all'}
VALID_SEVERITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}


def get_default_config():
    # type: () -> Dict[str, Any]
    """Return default configuration."""
    return {
        'version': 1,
        'exclude_paths': [],
        'exclude_patterns': [],
        'severity_threshold': None,
        'scan_types': ['secrets'],
        'custom_patterns': {},
        'entropy': {
            'enabled': False,
            'threshold': 4.5,
            'min_length': 20,
        },
    }


def find_config_file(scan_root=None):
    # type: (Optional[str]) -> Optional[str]
    """Search for .secchecker.yml in scan_root then cwd."""
    candidates = []
    if scan_root:
        candidates.append(os.path.join(str(scan_root), CONFIG_FILENAME))
    candidates.append(os.path.join(os.getcwd(), CONFIG_FILENAME))
    for path in candidates:
        if os.path.isfile(path):
            return path
    return None


def _parse_scalar(value_str):
    # type: (str) -> Any
    """Parse a YAML scalar string to a Python value."""
    if not value_str or value_str in ('null', 'Null', 'NULL', '~'):
        return None
    if value_str in ('true', 'True', 'yes', 'Yes'):
        return True
    if value_str in ('false', 'False', 'no', 'No'):
        return False
    try:
        return int(value_str)
    except ValueError:
        pass
    try:
        return float(value_str)
    except ValueError:
        pass
    if (value_str.startswith('"') and value_str.endswith('"')) or \
       (value_str.startswith("'") and value_str.endswith("'")):
        return value_str[1:-1]
    return value_str


def _parse_simple_yaml(text):
    # type: (str) -> Dict[str, Any]
    """
    Parse a bounded YAML subset for .secchecker.yml.
    Handles scalars, string lists, and one-level nested maps.
    Returns empty dict on any parse error.
    """
    result = {}
    lines = text.splitlines()
    i = 0

    while i < len(lines):
        line = lines[i].rstrip()
        if not line or line.lstrip().startswith('#'):
            i += 1
            continue

        top = re.match(r'^([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)', line)
        if top:
            key = top.group(1)
            value_str = top.group(2).strip()

            if value_str:
                result[key] = _parse_scalar(value_str)
                i += 1
            else:
                items = []
                nested = {}
                j = i + 1
                while j < len(lines):
                    next_line = lines[j].rstrip()
                    if not next_line:
                        j += 1
                        continue
                    list_m = re.match(r'^\s+-\s+(.+)', next_line)
                    map_m = re.match(r'^\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:\s*(.*)', next_line)
                    if list_m:
                        items.append(_parse_scalar(list_m.group(1).strip()))
                        j += 1
                    elif map_m:
                        nested[map_m.group(1)] = _parse_scalar(map_m.group(2).strip())
                        j += 1
                    else:
                        break

                if items:
                    result[key] = items
                elif nested:
                    result[key] = nested
                else:
                    result[key] = None
                i = j
        else:
            i += 1

    return result


def _validate_and_normalize(raw):
    # type: (Dict[str, Any]) -> Dict[str, Any]
    """Validate raw parsed config and merge with defaults."""
    config = get_default_config()
    if not isinstance(raw, dict):
        return config

    if isinstance(raw.get('exclude_paths'), list):
        config['exclude_paths'] = [str(p) for p in raw['exclude_paths']]

    if isinstance(raw.get('exclude_patterns'), list):
        config['exclude_patterns'] = [str(p) for p in raw['exclude_patterns']]

    threshold = raw.get('severity_threshold')
    if isinstance(threshold, str) and threshold.upper() in VALID_SEVERITIES:
        config['severity_threshold'] = threshold.upper()

    scan_types = raw.get('scan_types')
    if isinstance(scan_types, list):
        valid = [str(t) for t in scan_types if str(t) in VALID_SCAN_TYPES]
        if valid:
            config['scan_types'] = valid

    custom = raw.get('custom_patterns')
    if isinstance(custom, dict):
        config['custom_patterns'] = {str(k): str(v) for k, v in custom.items()}

    entropy = raw.get('entropy')
    if isinstance(entropy, dict):
        if isinstance(entropy.get('enabled'), bool):
            config['entropy']['enabled'] = entropy['enabled']
        if isinstance(entropy.get('threshold'), (int, float)):
            config['entropy']['threshold'] = float(entropy['threshold'])
        if isinstance(entropy.get('min_length'), int):
            config['entropy']['min_length'] = entropy['min_length']

    return config


def load_config(config_path=None, scan_root=None):
    # type: (Optional[str], Optional[str]) -> Dict[str, Any]
    """Load config from file or return defaults. Never raises."""
    if config_path is None:
        config_path = find_config_file(scan_root)

    if config_path is None:
        return get_default_config()

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            text = f.read()
        raw = _parse_simple_yaml(text)
        return _validate_and_normalize(raw)
    except Exception:
        return get_default_config()
