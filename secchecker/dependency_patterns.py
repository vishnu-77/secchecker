"""Dependency (npm/pnpm/Yarn package) security patterns.

Static content patterns applied to files inside a resolved dependency tree
(``node_modules/**`` or an extracted package directory) — obfuscation, shell
execution, network access, and credential access. Suspicious-binary and
lifecycle-hook detection are structural (filename/``package.json`` field
checks), handled in ``dependency_scanner.py``, but their finding categories
are listed here too so severity/OWASP lookups stay in one place per the
existing convention (see ``devsecops_patterns.py``).
"""
from typing import Dict, List

DEPENDENCY_PATTERNS: Dict[str, str] = {
    # ---- Obfuscation ----
    "Dependency - eval of decoded string": r"(?i)\beval\s*\(\s*(atob|Buffer\.from|decodeURIComponent|unescape)\s*\(",
    "Dependency - Function constructor from string": r"(?i)\bnew\s+Function\s*\(\s*[\'\"]",
    "Dependency - hex-escape-heavy string literal": r"(?:\\x[0-9a-fA-F]{2}){8,}",
    "Dependency - eval of variable": r"(?i)\beval\s*\(\s*[a-zA-Z_$][\w$]*\s*\)",

    # ---- Shell execution ----
    "Dependency - child_process exec": r"require\s*\(\s*[\'\"]child_process[\'\"]\s*\)|from\s+[\'\"]child_process[\'\"]",
    "Dependency - execSync/spawnSync call": r"\.(execSync|spawnSync)\s*\(",
    "Dependency - spawn with shell true": r"\.spawn\s*\([^)]*shell\s*:\s*true",

    # ---- Network access ----
    "Dependency - raw http/https/net module": r"require\s*\(\s*[\'\"](https?|net|dgram)[\'\"]\s*\)|from\s+[\'\"](https?|net|dgram)[\'\"]",
    "Dependency - fetch/XHR call": r"\bfetch\s*\(\s*[\'\"]https?://|new\s+XMLHttpRequest\s*\(",
    "Dependency - outbound request to raw IP": r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",

    # ---- Credential access ----
    "Dependency - bulk process.env read": r"(?:JSON\.stringify\s*\(\s*process\.env|Object\.(keys|entries|values)\s*\(\s*process\.env)",
    "Dependency - SSH/cloud credential path reference": r"(?i)[\'\"](?:[^\'\"]*\.ssh/id_rsa|[^\'\"]*\.aws/credentials|[^\'\"]*\.npmrc)[\'\"]",
    "Dependency - npm auth token pattern": r"//registry\.npmjs\.org/:_authToken\s*=",

    # ---- Structural (surfaced here for severity/OWASP consistency; detected
    #      in dependency_scanner.py, not via regex content match) ----
    "Dependency - Lifecycle hook script present": r"$^",   # never regex-matched; placeholder key
    "Dependency - Suspicious binary in package": r"$^",    # never regex-matched; placeholder key
    "Dependency - Lockfile integrity mismatch": r"$^",     # never regex-matched; placeholder key
}

# Structural finding categories (not scanned via re.findall against content —
# excluded from the regex loop in scan_file_dependency; listed above only so
# DEPENDENCY_SEVERITY_MAP / owasp.py stay indexed by the same set of names).
STRUCTURAL_CATEGORIES = frozenset({
    "Dependency - Lifecycle hook script present",
    "Dependency - Suspicious binary in package",
    "Dependency - Lockfile integrity mismatch",
})

DEPENDENCY_SEVERITY_MAP: Dict[str, str] = {
    "Dependency - eval of decoded string": "CRITICAL",
    "Dependency - Function constructor from string": "CRITICAL",
    "Dependency - execSync/spawnSync call": "CRITICAL",
    "Dependency - Lockfile integrity mismatch": "CRITICAL",
    "Dependency - child_process exec": "HIGH",
    "Dependency - spawn with shell true": "HIGH",
    "Dependency - bulk process.env read": "HIGH",
    "Dependency - SSH/cloud credential path reference": "HIGH",
    "Dependency - npm auth token pattern": "HIGH",
    "Dependency - Suspicious binary in package": "HIGH",
    "Dependency - Lifecycle hook script present": "MEDIUM",
    "Dependency - eval of variable": "MEDIUM",
    "Dependency - hex-escape-heavy string literal": "MEDIUM",
    "Dependency - raw http/https/net module": "MEDIUM",
    "Dependency - fetch/XHR call": "MEDIUM",
    "Dependency - outbound request to raw IP": "MEDIUM",
}

# Suspicious binary extensions/names checked structurally by the scanner.
SUSPICIOUS_BINARY_EXTENSIONS = {".exe", ".dll", ".so", ".dylib", ".node", ".bat", ".cmd", ".ps1"}
