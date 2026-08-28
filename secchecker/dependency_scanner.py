"""Dependency scanner — static, offline security checks for npm/pnpm/Yarn packages.

Scope (see THREAT_MODEL.md "Dependency scanning"): parses already-resolved
lockfiles and already-installed ``node_modules/`` content. Never runs `npm
install`, never executes a lifecycle script, never fetches anything over the
network. Package age/registry provenance is a separate, explicitly opt-in,
network-touching path (not implemented here — see ``--check-registry`` in
``cli.py``, off by default).

Follows the same two-function shape as every other scanner module
(``scan_file_X`` / ``scan_directory_X`` -> the shared
``Dict[str, List[str]]`` / ``Dict[str, Dict[str, List[str]]]`` result shape
that ``reporter.py``/``sarif_reporter.py``/``owasp.py`` already understand —
see ``devsecops_scanner.py`` for the closest existing analogue).
"""
import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from secchecker.core import should_skip_directory
from secchecker.dependency_patterns import (
    DEPENDENCY_PATTERNS,
    STRUCTURAL_CATEGORIES,
    SUSPICIOUS_BINARY_EXTENSIONS,
)

CONTENT_EXTENSIONS = {'.js', '.mjs', '.cjs', '.ts', '.jsx', '.tsx'}
LIFECYCLE_HOOK_NAMES = ('preinstall', 'install', 'postinstall', 'prepare')


# ---------------------------------------------------------------------------
# Lockfile / manifest parsers (stdlib only — no PyYAML, matching config.py's
# existing "bounded subset, hand-rolled" precedent for this codebase's
# zero-runtime-dependency policy).
# ---------------------------------------------------------------------------

def _read_text(filepath):
    # type: (str) -> Optional[str]
    for encoding in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, IOError):
            continue
    return None


def parse_package_lock(filepath):
    # type: (str) -> Dict[str, Dict[str, Any]]
    """Parse npm's package-lock.json (v2/v3 "packages" shape, with a v1
    "dependencies" fallback). Returns {"name@version": {version, integrity,
    resolved}}. Never raises — malformed/missing input returns {}.
    """
    text = _read_text(filepath)
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {}
    if not isinstance(data, dict):
        return {}

    entries: Dict[str, Dict[str, Any]] = {}

    packages = data.get('packages')
    if isinstance(packages, dict):
        for pkg_path, meta in packages.items():
            if not pkg_path or not isinstance(meta, dict):
                continue
            name = pkg_path.rsplit('node_modules/', 1)[-1]
            version = meta.get('version')
            if not name or not version:
                continue
            entries['{}@{}'.format(name, version)] = {
                'version': version,
                'integrity': meta.get('integrity'),
                'resolved': meta.get('resolved'),
            }
        return entries

    # v1 fallback: top-level "dependencies" map, one level (no recursive
    # transitive walk — v1 is legacy and increasingly rare; documented limit).
    deps = data.get('dependencies')
    if isinstance(deps, dict):
        for name, meta in deps.items():
            if not isinstance(meta, dict):
                continue
            version = meta.get('version')
            if not version:
                continue
            entries['{}@{}'.format(name, version)] = {
                'version': version,
                'integrity': meta.get('integrity'),
                'resolved': meta.get('resolved'),
            }
    return entries


def parse_pnpm_lock(filepath):
    # type: (str) -> Dict[str, Dict[str, Any]]
    """Parse the "packages:" section of pnpm-lock.yaml.

    Bounded subset parser (same philosophy as config.py's _parse_simple_yaml):
    handles the common "packages:" block with "/name@version:" or
    "name@version:" keys and a nested "resolution: {integrity: ...}" or bare
    "integrity:" line. Does not attempt full YAML — pnpm-lock.yaml's schema
    has changed across lockfileVersion generations; this covers the current
    (v6/v9-era) shape. Never raises.
    """
    text = _read_text(filepath)
    if text is None:
        return {}

    entries: Dict[str, Dict[str, Any]] = {}
    lines = text.splitlines()
    in_packages = False
    current_key: Optional[str] = None

    key_re = re.compile(r"^\s{2}(?:/)?([^\s:'\"]+)@([^\s:'\"]+)(?:\([^)]*\))?:\s*$")
    # Two shapes seen across pnpm-lock.yaml generations: a bare "integrity:"
    # line, or "resolution: {integrity: sha512-...}" as an inline YAML flow
    # mapping (the current v6/v9 shape).
    integrity_re = re.compile(r"^\s+integrity:\s*(\S+?),?\s*$")
    inline_integrity_re = re.compile(r"^\s+resolution:\s*\{[^}]*integrity:\s*([^,}\s]+)")

    for line in lines:
        if line.startswith('packages:'):
            in_packages = True
            continue
        if not in_packages:
            continue
        if line and not line.startswith(' '):
            # Dedented back to top level — packages: block ended.
            if not line.startswith('packages'):
                in_packages = False
            continue

        m = key_re.match(line)
        if m:
            name, version = m.group(1), m.group(2)
            current_key = '{}@{}'.format(name, version)
            entries[current_key] = {'version': version, 'integrity': None, 'resolved': None}
            continue

        if current_key:
            im = inline_integrity_re.match(line) or integrity_re.match(line)
            if im:
                entries[current_key]['integrity'] = im.group(1)

    return entries


def parse_yarn_lock(filepath):
    # type: (str) -> Dict[str, Dict[str, Any]]
    """Parse yarn.lock (Yarn's own format — not YAML or JSON).

    Blocks are separated by blank lines; a block's header line(s) end in
    ':' and list comma-separated specifiers, indented lines are
    'key "value"' pairs. Never raises.
    """
    text = _read_text(filepath)
    if text is None:
        return {}

    entries: Dict[str, Dict[str, Any]] = {}
    block: List[str] = []

    def _flush(block_lines):
        if not block_lines:
            return
        header = block_lines[0]
        if not header.endswith(':'):
            return
        specifiers = [s.strip().strip('"') for s in header[:-1].split(',')]
        version = integrity = resolved = None
        for line in block_lines[1:]:
            stripped = line.strip()
            vm = re.match(r'^version\s+"?([^"\s]+)"?$', stripped)
            if vm:
                version = vm.group(1)
                continue
            im = re.match(r'^integrity\s+(\S+)$', stripped)
            if im:
                integrity = im.group(1)
                continue
            rm = re.match(r'^resolved\s+"([^"]+)"$', stripped)
            if rm:
                resolved = rm.group(1)
        if version is None:
            return
        for spec in specifiers:
            name = spec.rsplit('@', 1)[0] if '@' in spec[1:] else spec
            entries['{}@{}'.format(name, version)] = {
                'version': version, 'integrity': integrity, 'resolved': resolved,
            }

    for raw_line in text.splitlines():
        if raw_line.startswith('#') or not raw_line.strip():
            if raw_line.strip() == '' and block:
                _flush(block)
                block = []
            continue
        block.append(raw_line)
    _flush(block)

    return entries


LOCKFILE_PARSERS = {
    'package-lock.json': parse_package_lock,
    'pnpm-lock.yaml': parse_pnpm_lock,
    'yarn.lock': parse_yarn_lock,
}


def parse_lockfile(filepath):
    # type: (str) -> Dict[str, Dict[str, Any]]
    """Dispatch to the right parser by filename. Unknown filename -> {}."""
    name = Path(filepath).name
    parser = LOCKFILE_PARSERS.get(name)
    if parser is None:
        return {}
    return parser(filepath)


def diff_lockfiles(old_entries, new_entries):
    # type: (Dict[str, Dict[str, Any]], Dict[str, Dict[str, Any]]) -> List[str]
    """Compare two parsed lockfile snapshots (e.g. git HEAD vs working tree).

    Returns human-readable strings describing packages whose *integrity*
    changed while the package name stayed pinned to the same declared
    version-key in both — a mismatched hash for the same key is the
    supply-chain-relevant signal (a silent republish/tamper), not a normal
    version bump (which is a new key, not a diff, and not itself suspicious).
    """
    changes: List[str] = []
    for key, new_meta in new_entries.items():
        old_meta = old_entries.get(key)
        if old_meta is None:
            continue
        old_int, new_int = old_meta.get('integrity'), new_meta.get('integrity')
        if old_int and new_int and old_int != new_int:
            changes.append(
                '{}: integrity changed ({} -> {})'.format(key, old_int, new_int)
            )
    return changes


# ---------------------------------------------------------------------------
# package.json lifecycle hook detection
# ---------------------------------------------------------------------------

def find_lifecycle_hooks(package_dir):
    # type: (str) -> Dict[str, str]
    """Read one package's own package.json 'scripts' block and return the
    subset of preinstall/install/postinstall/prepare hooks present, as
    {hook_name: script_command}. {} if no package.json, no scripts, or
    unparseable — never raises.
    """
    pkg_json_path = os.path.join(package_dir, 'package.json')
    text = _read_text(pkg_json_path)
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return {}
    scripts = data.get('scripts') if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}
    return {
        hook: str(scripts[hook])
        for hook in LIFECYCLE_HOOK_NAMES
        if hook in scripts and scripts[hook]
    }


# ---------------------------------------------------------------------------
# Content pattern scanning (same shape/behavior as devsecops_scanner.py)
# ---------------------------------------------------------------------------

def scan_file_dependency(filepath):
    # type: (str) -> Dict[str, List[str]]
    """Scan a single JS/TS file inside a dependency tree for content
    patterns (obfuscation, shell-exec, network, credential-access).
    Structural categories (hooks, binaries, lockfile drift) are NOT produced
    here — see scan_directory_dependency, which also handles those.
    """
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return {}
    try:
        if path.stat().st_size > 10 * 1024 * 1024:
            return {}
    except OSError:
        return {}

    content = _read_text(filepath)
    if content is None:
        return {}

    findings: Dict[str, List[str]] = {}
    for pattern_name, pattern_regex in DEPENDENCY_PATTERNS.items():
        if pattern_name in STRUCTURAL_CATEGORIES:
            continue
        try:
            matches = re.findall(pattern_regex, content)
        except re.error:
            continue
        if matches:
            flat = [m if isinstance(m, str) else ' '.join(m) for m in matches]
            seen: set = set()
            deduped = [x for x in flat if not (x in seen or seen.add(x))]
            findings[pattern_name] = deduped
    return findings


def _is_suspicious_binary(filepath):
    # type: (str) -> bool
    return Path(filepath).suffix.lower() in SUSPICIOUS_BINARY_EXTENSIONS


def scan_directory_dependency(directory, lockfile_entries=None):
    # type: (str, Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, Dict[str, List[str]]]
    """Scan a node_modules tree (or any directory containing one) for
    content patterns plus structural findings (lifecycle hooks, suspicious
    binaries). Deliberately does NOT prune 'node_modules' the way every
    other scanner's should_skip_directory does (core.py SKIP_DIRS) — that
    directory is exactly what this scanner exists to look inside.

    lockfile_entries, if given (from parse_lockfile), currently isn't used
    for byte-level integrity verification here — see the module docstring
    and diff_lockfiles(): tarball-integrity hashes can't be reliably
    reproduced from an already-extracted node_modules tree without
    re-packing it identically to npm's own tar process, so that check is
    intentionally not attempted (would produce false positives). Lockfile
    drift is checked separately via diff_lockfiles() against a prior
    snapshot (e.g. git history), not against installed files.
    """
    if not os.path.exists(directory):
        raise FileNotFoundError('Directory not found: {}'.format(directory))

    results: Dict[str, Dict[str, List[str]]] = {}
    directory_path = Path(directory)

    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        # Reuse the shared skip-list (VCS, caches, .venv, dist, ...) but
        # deliberately do NOT prune node_modules — that's exactly what this
        # scanner exists to look inside.
        dirs[:] = [d for d in dirs if d == 'node_modules' or
                   (d != '.bin' and not should_skip_directory(Path(d)))]

        # This is a *dependency* scanner: only look at files that are
        # actually inside a node_modules tree. Without this, "suspicious
        # binary" and "lifecycle hook" checks would fire on the scanned
        # project's own dev scripts/binaries — false positives outside this
        # scanner's job (first-party source is every other scanner's job).
        if 'node_modules' not in root_path.parts:
            continue

        for filename in files:
            file_path = root_path / filename
            file_findings: Dict[str, List[str]] = {}

            if filename == 'package.json':
                hooks = find_lifecycle_hooks(str(root_path))
                if hooks:
                    file_findings['Dependency - Lifecycle hook script present'] = [
                        '{}: {}'.format(name, cmd) for name, cmd in hooks.items()
                    ]

            if _is_suspicious_binary(str(file_path)):
                file_findings.setdefault(
                    'Dependency - Suspicious binary in package', []
                ).append(filename)

            if Path(filename).suffix.lower() in CONTENT_EXTENSIONS:
                content_findings = scan_file_dependency(str(file_path))
                for k, v in content_findings.items():
                    file_findings.setdefault(k, []).extend(v)

            if file_findings:
                try:
                    rel = file_path.relative_to(directory_path)
                    results[str(rel)] = file_findings
                except ValueError:
                    results[str(file_path)] = file_findings

    return results
