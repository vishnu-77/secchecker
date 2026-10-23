"""Config file loader for secchecker — parses .secchecker.yml using stdlib only."""
import os
import re
import fnmatch
from pathlib import Path
from typing import Any, Dict, List, Optional

CONFIG_FILENAME = '.secchecker.yml'
VALID_SCAN_TYPES = {'secrets', 'llm', 'devsecops', 'dependency', 'all'}
VALID_SEVERITIES = {'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}


class ConfigError(ValueError):
    """Raised when strict configuration loading cannot safely continue."""


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
        'dependency_scan': {
            'check_registry': False,
            'block_at': 'CRITICAL',
            'review_at': 'HIGH',
            'warn_at': 'MEDIUM',
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
    if value_str and value_str[0] in ('"', "'"):
        quote = value_str[0]
        end = value_str.find(quote, 1)
        if end != -1:
            return value_str[1:end]
    hash_idx = value_str.find(' #')
    if hash_idx != -1:
        value_str = value_str[:hash_idx].rstrip()
    return value_str


def _parse_simple_yaml(text, strict=False):
    # type: (str, bool) -> Dict[str, Any]
    """
    Parse a bounded YAML subset for .secchecker.yml.

    Handles scalars, string lists, and one-level nested maps. In permissive
    mode unsupported syntax is ignored for backwards compatibility. In strict
    mode malformed/unsupported syntax raises ConfigError so a security scan
    cannot silently fall back to weaker defaults.
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
                    if not next_line or next_line.lstrip().startswith('#'):
                        j += 1
                        continue

                    # A dedented line belongs to the next top-level key.
                    if next_line == next_line.lstrip():
                        break

                    list_m = re.match(r'^\s+-\s+(.+)', next_line)
                    map_m = re.match(
                        r'^\s+([a-zA-Z_][a-zA-Z0-9_]*|"[^"]*"|\'[^\']*\')\s*:\s*(.*)',
                        next_line,
                    )
                    if list_m:
                        items.append(_parse_scalar(list_m.group(1).strip()))
                        j += 1
                    elif map_m:
                        mk = map_m.group(1)
                        if (mk.startswith('"') and mk.endswith('"')) or \
                           (mk.startswith("'") and mk.endswith("'")):
                            mk = mk[1:-1]
                        nested[mk] = _parse_scalar(map_m.group(2).strip())
                        j += 1
                    else:
                        if strict:
                            raise ConfigError(
                                "Unsupported configuration syntax at line {}: {}".format(
                                    j + 1, next_line.strip()
                                )
                            )
                        break

                if items and nested:
                    if strict:
                        raise ConfigError(
                            "Configuration key '{}' mixes list and map values".format(key)
                        )
                    result[key] = items
                elif items:
                    result[key] = items
                elif nested:
                    result[key] = nested
                else:
                    result[key] = None
                i = j
        else:
            if strict:
                raise ConfigError(
                    "Unsupported configuration syntax at line {}: {}".format(i + 1, line.strip())
                )
            i += 1

    return result


def _require_type(raw, key, expected, strict):
    if strict and key in raw and raw.get(key) is not None and not isinstance(raw.get(key), expected):
        raise ConfigError("Invalid type for configuration key '{}'".format(key))


def _validate_and_normalize(raw, strict=False):
    # type: (Dict[str, Any], bool) -> Dict[str, Any]
    """Validate raw parsed config and merge with defaults."""
    config = get_default_config()
    if not isinstance(raw, dict):
        if strict:
            raise ConfigError('Configuration root must be a mapping')
        return config

    _require_type(raw, 'exclude_paths', list, strict)
    if isinstance(raw.get('exclude_paths'), list):
        config['exclude_paths'] = [str(p) for p in raw['exclude_paths']]

    _require_type(raw, 'exclude_patterns', list, strict)
    if isinstance(raw.get('exclude_patterns'), list):
        config['exclude_patterns'] = [str(p) for p in raw['exclude_patterns']]

    threshold = raw.get('severity_threshold')
    if threshold is not None:
        if isinstance(threshold, str) and threshold.upper() in VALID_SEVERITIES:
            config['severity_threshold'] = threshold.upper()
        elif strict:
            raise ConfigError("Invalid severity_threshold: {!r}".format(threshold))

    scan_types = raw.get('scan_types')
    if scan_types is not None:
        if not isinstance(scan_types, list):
            if strict:
                raise ConfigError('scan_types must be a list')
        else:
            invalid = [str(t) for t in scan_types if str(t) not in VALID_SCAN_TYPES]
            if invalid and strict:
                raise ConfigError('Invalid scan_types: {}'.format(', '.join(invalid)))
            valid = [str(t) for t in scan_types if str(t) in VALID_SCAN_TYPES]
            if valid:
                config['scan_types'] = valid

    custom = raw.get('custom_patterns')
    if custom is not None:
        if not isinstance(custom, dict):
            if strict:
                raise ConfigError('custom_patterns must be a mapping')
        else:
            normalized = {str(k): str(v) for k, v in custom.items()}
            if strict:
                for name, pattern in normalized.items():
                    try:
                        re.compile(pattern)
                    except re.error as exc:
                        raise ConfigError(
                            "Invalid custom pattern '{}': {}".format(name, exc)
                        )
            config['custom_patterns'] = normalized

    entropy = raw.get('entropy')
    if entropy is not None:
        if not isinstance(entropy, dict):
            if strict:
                raise ConfigError('entropy must be a mapping')
        else:
            if 'enabled' in entropy:
                if isinstance(entropy.get('enabled'), bool):
                    config['entropy']['enabled'] = entropy['enabled']
                elif strict:
                    raise ConfigError('entropy.enabled must be boolean')
            if 'threshold' in entropy:
                if isinstance(entropy.get('threshold'), (int, float)):
                    config['entropy']['threshold'] = float(entropy['threshold'])
                elif strict:
                    raise ConfigError('entropy.threshold must be numeric')
            if 'min_length' in entropy:
                if isinstance(entropy.get('min_length'), int):
                    config['entropy']['min_length'] = entropy['min_length']
                elif strict:
                    raise ConfigError('entropy.min_length must be an integer')

    dep_scan = raw.get('dependency_scan')
    if dep_scan is not None:
        if not isinstance(dep_scan, dict):
            if strict:
                raise ConfigError('dependency_scan must be a mapping')
        else:
            if 'check_registry' in dep_scan:
                if isinstance(dep_scan.get('check_registry'), bool):
                    config['dependency_scan']['check_registry'] = dep_scan['check_registry']
                elif strict:
                    raise ConfigError('dependency_scan.check_registry must be boolean')
            for key in ('block_at', 'review_at', 'warn_at'):
                if key not in dep_scan:
                    continue
                val = dep_scan.get(key)
                if isinstance(val, str) and val.upper() in VALID_SEVERITIES:
                    config['dependency_scan'][key] = val.upper()
                elif strict:
                    raise ConfigError(
                        "dependency_scan.{} must be one of {}".format(
                            key, ', '.join(sorted(VALID_SEVERITIES))
                        )
                    )

    return config


def is_path_excluded(rel_path, exclude_paths):
    # type: (str, Optional[List[str]]) -> bool
    """
    Return True if ``rel_path`` matches any entry in ``exclude_paths``.

    Matching rules (case-sensitive, separator-agnostic):
      * A glob entry (contains ``*``, ``?`` or ``[``) is matched with fnmatch
        against both the full path and its basename.
      * A plain entry matches when it appears as a full path component.
      * A multi-segment literal matches that exact file or a nested path.
    """
    if not exclude_paths:
        return False

    norm = str(rel_path).replace('\\', '/').strip('/')
    if not norm:
        return False
    segments = norm.split('/')

    for raw in exclude_paths:
        if not raw:
            continue
        pat = str(raw).replace('\\', '/').strip().strip('/')
        if not pat:
            continue

        if any(ch in pat for ch in '*?['):
            if fnmatch.fnmatch(norm, pat) or fnmatch.fnmatch(segments[-1], pat):
                return True
            continue

        if '/' in pat:
            if norm == pat or norm.startswith(pat + '/'):
                return True
        else:
            if pat in segments:
                return True

    return False


def is_pattern_excluded(pattern_name, exclude_patterns):
    # type: (str, Optional[List[str]]) -> bool
    """Return True if finding category matches an excluded name/glob."""
    if not exclude_patterns:
        return False
    name = str(pattern_name).lower()
    for raw in exclude_patterns:
        if raw and fnmatch.fnmatch(name, str(raw).lower()):
            return True
    return False


def load_config(config_path=None, scan_root=None, strict=False):
    # type: (Optional[str], Optional[str], bool) -> Dict[str, Any]
    """Load configuration.

    ``strict=False`` preserves the library's historical fail-soft behaviour.
    ``strict=True`` is intended for CLI/CI use: missing explicit files,
    malformed syntax, invalid security thresholds/types and invalid custom
    regexes raise ConfigError instead of silently reverting to defaults.
    """
    explicit_path = config_path is not None
    if config_path is None:
        config_path = find_config_file(scan_root)

    if config_path is None:
        return get_default_config()

    if not os.path.isfile(config_path):
        if strict and explicit_path:
            raise ConfigError('Configuration file not found: {}'.format(config_path))
        return get_default_config()

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            text = f.read()
        raw = _parse_simple_yaml(text, strict=strict)
        return _validate_and_normalize(raw, strict=strict)
    except ConfigError:
        if strict:
            raise
        return get_default_config()
    except Exception as exc:
        if strict:
            raise ConfigError(
                'Could not load configuration {}: {}'.format(config_path, exc)
            )
        return get_default_config()
