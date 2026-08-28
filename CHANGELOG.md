# Changelog

All notable changes to secchecker are documented here.

---

## [0.4.2] — 2026-07-17

An independent audit of 0.4.0 found the default scan crashing on current Python, a
severity-filtering bug that could report a dirty repo as clean, and several config
options that were parsed but silently ignored. This release fixes all of it and adds
a regression test per bug.

### Fixed
- **Default scan crashed on Python 3.14** (`ast_scanner.py`) — the AST scanner read
  the deprecated `ast.Constant.s` alias, which was removed in Python 3.14. `secchecker
  <path>` (the default `secrets` scan) and `--type all` now run cleanly on Python
  3.8–3.14 instead of crashing with exit code 2 and no report.
- **`--severity-threshold` could silently drop real findings** — AST-detected
  `eval`/`exec` calls, hardcoded secrets, and tainted-sink findings (plus several
  secrets patterns and the entropy finding) had no explicit severity and defaulted to
  `LOW`, so `--severity-threshold HIGH` dropped them and reported a clean scan for a
  vulnerable file. Every finding category now has an explicit severity, enforced by a
  new contract test (`tests/test_severity_contract.py`) so this class of bug can't
  silently recur.
- **Bearer-scheme findings were always suppressed** (`validators.py`) — JWT structural
  validation was incorrectly applied to bearer-scheme values as well as JWTs; since a
  match includes the literal `Bearer` prefix plus a following value, it could never
  pass JWT validation. These findings are now validated only against the universal
  placeholder filter.
- **Entropy scan results used inconsistent keys** — the entropy walk keyed findings by
  absolute path while the regex/AST scanners use paths relative to the scan root, so
  the same file could appear twice in results, and entropy scanning skipped none of
  the usual excluded directories (`node_modules`, `.git`, etc.). Entropy now shares
  the same relative-path keys and skip filters as the other scanners, and honors
  `entropy.threshold` / `entropy.min_length` from `.secchecker.yml` (previously parsed
  but never applied).
- **DevSecOps findings shipped with empty OWASP/CWE tags in SARIF** — `owasp.py`'s
  DevSecOps entries used stale pattern names that no longer matched
  `DEVSECOPS_PATTERNS`. All 25 DevSecOps rules are now correctly tagged.

### Added
- **MCP tool-poisoning detection for the canonical attack** — hidden instructions
  embedded in a tool function's docstring or a `description=`/tool-schema value
  (e.g. `<IMPORTANT>ignore previous instructions...</IMPORTANT>`), the way a poisoned
  tool actually hijacks a calling LLM. Two new findings, both HIGH:
  `MCP - Poisoned Tool Docstring` and `MCP - Poisoned Tool Description`. AST-based and
  runs under `--type llm`.
- **`--pii` flag** — Email and Phone Number detection moved out of the default secrets
  scan (previously produced alert fatigue on ordinary codebases) into an opt-in flag.
- **`exclude_patterns` config key wired up** — case-insensitive glob exclusion of
  finding *categories* by rule name (e.g. `"Email"`, `"LLM - *"`), applied after all
  scanners run. Distinct from `exclude_paths`, which excludes files.
- **`custom_patterns` config key wired up** — user-defined `{name: regex}` patterns
  are now merged into the secrets scan instead of being parsed and discarded.
- **`scan_types` config key wired up** — used as the default scan type when `--type`
  is not passed on the command line; `--type` always takes precedence.
- CI matrix extended to Python 3.13 and 3.14 (previously stopped at 3.12, which is why
  the Python 3.14 crash above shipped undetected).

### Changed
- Documentation counts corrected to match actual pattern counts: 56 secrets patterns
  (was documented as "52+") plus 2 opt-in PII patterns via `--pii`; 18 LLM patterns
  plus 11 MCP/agentic patterns (was "9"); 25 DevSecOps patterns (was documented as
  "28+", an over-claim). Entropy scanning documented as config opt-in, not
  enabled-by-default. README gained a Limitations section.

---

## [0.4.1] — 2026-07-11

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
