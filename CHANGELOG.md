# Changelog

All notable changes to secchecker are documented here.

---

## [0.5.1] — 2026-09-10

A correctness release. Nothing here is new capability: it is what running the
scanner against real open-source agent repositories, and auditing the two
documented entry points, turned up. Both entry points were broken.

### Fixed
- **Pre-commit hooks never scanned anything.** All three hooks in
  `.pre-commit-hooks.yaml` set `pass_filenames: false` and passed no path, but `path`
  is a required positional on `scan` — so every invocation exited 2 with an argparse
  usage error rather than scanning. Exit 2 also reads as a hard runtime error to the
  GitHub Action wrapper, not as "findings present".
- **The GitHub Action defaulted to the wrong scanner.** `action.yml` defaulted `type`
  to `secrets`, the legacy scanner, while the README's documented usage and the
  project's positioning both lead with `--type llm`. Anyone copying the Action snippet
  without an explicit `type:` silently got the wrong analysis.
- **False positives from lexical co-occurrence** (`llm_scanner.py`). Triaging six real
  agent repositories (`bench/agentsecbench/`) showed 8 of 10 labelled HIGH/CRITICAL
  findings were false, 7 of them from one root cause: rules keyed on keywords appearing
  near each other rather than on a value reaching a sink. The sharpest case flagged the
  code that *redacts* credentials from an LLM sandbox as the leak. Three narrow guards
  — an LLM-call sink check, a value-vs-name check, and an MCP-marker check — remove 6
  of the 8. Not a taint engine; one extra condition per rule, over text the rule already
  scanned.
- **`secchecker --version` did not work.** It hit the implicit-`scan` shim in
  `cli.main()`, which only let `-h`/`--help` through, and died with "the following
  arguments are required: path". There was no top-level `--version` flag at all.
  Added, with `tests/test_cli_contract.py` covering it and the
  `secchecker <path>` shorthand it must not break.
- **Quadratic scan cost on large files** — two DOTALL regexes replaced with AST checks.
  The 10 MB size guard was already present but insufficient at realistic file sizes.
- **`Args:` docstrings misread as instruction overrides** — a `system:` marker on a
  documented `system` parameter is no longer a poisoned-docstring finding (AST check).

### Added
- Provider key patterns for Groq, OpenRouter, xAI and LangSmith, with OWASP/CWE
  mappings.
- `tests/test_benchmark_claims.py` — asserts every precision/recall figure quoted in
  the docs against `bench/results/<version>.json`, and fails on any `N/14` that
  disagrees. Written because the adversarial score had drifted to four different values
  across four files.
- `bench/results/0.5.1.json` — the corpus re-measured on this release.

### Changed
- **`Development Status :: 5 - Production/Stable` → `4 - Beta`.** Measured precision on
  real-world code is 20% and adversarial recall is 28.6%. Production/Stable overstated
  that.
- Claims scoped to what the code covers: AST analysis and the MCP tool-poisoning check
  are Python-only, so the roadmap now says "for Python MCP servers". The
  supported-ecosystems table no longer implies broad LangChain coverage from a single
  pattern.
- README imagery reduced to the banner; `brand/render_assets.py` synced so a render
  reproduces it.

### Unchanged, deliberately
The synthetic regression corpus still scores 1.00/1.00 and the adversarial corpus still
scores 4/14. The guards above were validated against real repositories, not against
these fixtures — the synthetic scores staying flat is the no-regression signal, not
evidence the guards worked.

---

## [0.5.0] — 2026-09-08

Dependency scanning, a real precision/recall benchmark (including the first honest
adversarial number this project has published), and a README rebuilt around a
20-second quickstart.

### Added
- **npm/pnpm/Yarn dependency scanning** (`dependency_scanner.py`, `dependency_patterns.py`,
  `dependency_policy.py`) — static, offline pre-install checks: obfuscated code, shell
  execution, undisclosed install hooks, suspicious binaries, lockfile integrity drift.
  New CLI surface: `secchecker . --type dependency`, `secchecker package inspect`,
  `secchecker scripts review`, `secchecker verify`. Never runs an install, never
  executes a lifecycle script — see `THREAT_MODEL.md`.
- **Adversarial benchmark corpus** (`bench/fixtures/adversarial/`, 14 fixtures) — the
  same vulnerabilities as the existing regression corpus, deliberately paraphrased or
  reshaped (different variable names, `%`-formatting instead of `.format()`,
  `subprocess.call` instead of `.run`, a UK NI number instead of an SSN). **Result:
  4/14 caught (28.6% recall)** — the honest number the regression corpus's 1.00 can't
  show. See `bench/methodology.md`.
- **benign_realistic corpus** (`bench/fixtures/benign_realistic/`, 4 fixtures) — curated
  plausible-false-positive shapes. **Result: 2/4 still flagged**, documenting a known
  static-analysis limitation rather than a bug.
- **Scan-throughput benchmark** (`bench/perf.py`) — asserts scan time scales roughly
  linearly with file count; wired into CI as an informational (non-blocking) step
  alongside `bench/run.py`.
- **SARIF output validated against the real SARIF 2.1.0 JSON Schema**
  (`tests/test_sarif_schema.py`), not just bespoke structural assertions.

### Fixed
- **SARIF `region.startLine` was hardcoded to `1`** for every finding — now reports the
  real match line (best-effort re-location; the scanner pipeline doesn't carry match
  offsets end-to-end, so this isn't a full data-model change).
- **Scanner regex patterns were recompiled per file, per pattern** instead of compiled
  once at import — fragile (relied on the implicit interpreter-level regex cache) and
  a real, now-benchmarked perf cost. Confirmed via `bench/perf.py`: ~121 files/s, flat
  across 400→1600 files.
- **CI never installed the `jsonschema` test dependency** — `tests/test_sarif_schema.py`
  failed collection on every run until `ci.yml` switched to `pip install -e ".[test]"`.

### Changed
- **README rebuilt around a 20-second quickstart** — name, one-sentence positioning,
  a real flagged-vs-clean example (verified live against `bench/fixtures/`), install,
  architecture, then everything else moved below the fold. Softened absolute claims
  ("detects patterns associated with," not "finds"/"prevents").
- `pyproject.toml` description aligned to match.

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
