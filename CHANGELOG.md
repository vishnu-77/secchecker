# Changelog

All notable changes to secchecker are documented here.

---

## [Unreleased]

### Fixed
- `exclude_paths` in `.secchecker.yml` is now enforced. Previously it was parsed
  from config but never applied, so configured exclusions had no effect. Findings
  in matching files are now dropped after scanning, covering every scanner
  (secrets, LLM/MCP/agentic, DevSecOps, AST, entropy) with one rule. Supports
  directory prefixes (`tests/`), path components (`node_modules`), globs
  (`*.mock.*`), and multi-segment literals (`secchecker/patterns.py`).
- Config parser now strips trailing inline comments (`- "demo/"  # note`) and
  skips full-line comments interspersed between list items, so commented
  `.secchecker.yml` files parse as intended instead of silently dropping entries.

### Changed
- The repository now ships a `.secchecker.yml` that excludes its own pattern
  definitions, fixtures, sample reports, and demo from the self-scan. The
  Security Scan workflow again uploads SARIF to the GitHub Security tab, now
  free of self-referential false positives.

---

## [0.4.0] — 2026-07-08

### Added
- Added MCP security patterns for unvalidated tool results, direct tool output execution, hardcoded MCP server URLs, and untrusted tool descriptions.
- Added agentic AI security patterns for memory injection, unbounded agent loops, unvalidated function call results, recursive self-invocation, and PII passed to external agents.
- Added OWASP LLM Top 10 mappings for new MCP and agentic AI findings.

### Improved
- Repositioned secchecker around AI agents, MCP tools, and LLM application security.
- Updated package metadata and README to reflect AI/GenAI/MCP-first positioning.
- Updated CLI examples to lead with LLM/MCP scanning.

### Fixed
- `get_severity()` now resolves LLM/AI and DevSecOps pattern severities instead of defaulting every non-secret finding to LOW. This corrects severity in the JSON, Markdown, XML, SARIF, and HTML reporters and in the `--severity-threshold` filter.
- The GitHub Action now passes the `type` input through to the scanner (`--type`) and fails on exit code 2 (runtime/config/reporting errors) instead of treating them as success.
- Removed unsafe `|| true` from CI smoke tests so genuine runtime errors (exit code 2) fail the build; release-validation smoke tests now exercise the installed wheel across JSON, SARIF, and HTML formats.

### Notes
- The default scan type remains `secrets` for backward compatibility. Lead with `secchecker . --type llm` for AI/MCP scanning; a default change is under consideration for a future major release.
- Secret scanning and DevSecOps checks remain supported through explicit scan types and `--type all`.

---

## [0.3.0] — 2025-06-01

### Added

- **LLM / AI security scanner** — 18+ patterns covering prompt injection via f-strings and format(), hardcoded jailbreak instructions, role override patterns, RAG database queries and raw file reads in LLM context, eval/exec of model output, LangChain unsafe input, secrets passed to LLM, and hardcoded AI API keys (OpenAI, Anthropic, HuggingFace, Pinecone, Weaviate)
- **DevSecOps scanner** — 28+ patterns across Dockerfile (unpinned base images, secrets in ENV, curl-pipe-bash, root user), Kubernetes (privileged containers, hostNetwork, privilege escalation), Terraform (open security groups, public S3 buckets, plaintext credentials), and CI/CD (secrets in logs, pull_request_target misuse, unpinned actions)
- **Shannon entropy detection** — charset-aware thresholds (base64 >= 4.5, hex >= 3.0) to catch unknown secrets that don't match any known pattern
- **AST-based Python scanner** — structural analysis of .py files: hardcoded secrets in assignments, eval/exec detection, and taint tracking from user-controlled sources to dangerous sinks
- **OWASP mapping** — OWASP Top 10 (2021) and OWASP LLM Top 10 (2025) classifications for all patterns, embedded in SARIF output
- **Post-match validators** — Luhn algorithm for credit card validation, JWT structural verification, and placeholder suppression to reduce false positives
- **SARIF 2.1.0 reporter** — output compatible with the GitHub Security tab, including OWASP/CWE tags per rule
- **HTML reporter** — self-contained single-file HTML reports with severity badges and summary statistics
- **Config file support** — .secchecker.yml for per-project scan configuration: severity threshold, excluded paths, scan types, entropy settings, and custom patterns
- **CLI rewrite** — --type, --format, --severity-threshold, --config, --no-entropy, --verbose flags; exit codes 0 (no findings), 1 (findings), 2 (error)
- **GitHub Action** — composite action with SARIF upload support
- **CI pipeline** — matrix testing across Python 3.8–3.12, PyPI Trusted Publishing via OIDC

### Changed

- All scanners share a single file-filtering contract via should_skip_file() / should_skip_directory() in core.py
- Package classifier upgraded to Production/Stable

---

## [0.2.1] — 2025-04-15

### Fixed

- XML indentation compatibility for Python 3.8 (custom _indent_xml() fallback)
- License field format updated to comply with PEP 621

---

## [0.2.0] — 2025-03-01

### Added

- Enhanced JSON reporter with metadata, severity counts, and per-finding severity
- Enhanced Markdown reporter with severity breakdown
- Enhanced XML reporter with summary section and severity counts
- get_scan_stats() utility
- File size limit (10 MB) to skip large binary or generated files

### Changed

- Findings deduplicated per pattern per file before reporting
- Binary and generated file extensions expanded in skip list

---

## [0.1.0] — 2025-01-01

### Added

- Initial release
- Regex-based secret scanner covering AWS keys, private keys, database URIs, GitHub/GitLab tokens, JWT tokens, and config passwords
- JSON, Markdown, and XML output formats
- scan_file() and scan_directory() Python API
- CLI entry point via secchecker command
- Python 3.8–3.12 compatibility
- Zero runtime dependencies
