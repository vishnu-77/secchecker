[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Downloads](https://img.shields.io/pypi/dm/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![codecov](https://codecov.io/gh/vishnu-77/secchecker/branch/main/graph/badge.svg)](https://codecov.io/gh/vishnu-77/secchecker)

# secchecker

**Security auditing for DevSecOps pipelines and AI systems — in a single command.**

secchecker finds hardcoded secrets, AI/LLM vulnerabilities, and infrastructure misconfigurations before they reach production. It covers the three layers most tools treat separately: source code secrets, AI application security, and infrastructure-as-code hygiene. Zero external dependencies. Runs anywhere Python runs.

> The only PyPI static analysis tool with a dedicated LLM/AI security scanner.

---

## The problem it solves

Modern applications have three distinct attack surfaces that legacy scanners address poorly:

**Source code** — Developers commit API keys, database credentials, and private keys directly into repositories. These persist in git history long after deletion.

**AI and LLM applications** — Teams building on top of OpenAI, Anthropic, or open-source models introduce new vulnerability classes: prompt injection, RAG data leakage, insecure output handling, and hardcoded model API keys. No mainstream PyPI scanner covers these.

**Infrastructure as code** — Terraform modules, Kubernetes manifests, Dockerfiles, and CI/CD pipelines contain misconfigurations that open production environments to privilege escalation, data exposure, and supply chain attacks.

secchecker audits all three in one pass.

---

## Coverage at a glance

| Scanner | What it detects | Patterns |
|---------|----------------|---------|
| Secrets | Cloud keys, private keys, database URIs, payment credentials, service tokens | 52+ |
| LLM / AI | Prompt injection, RAG leakage, eval of model output, hardcoded AI API keys | 18+ |
| DevSecOps | Dockerfile, Kubernetes, Terraform, CI/CD misconfigurations | 28+ |
| Entropy | Unknown secrets with high Shannon entropy — catches what regex misses | — |
| AST | Hardcoded secrets in Python assignments, eval/exec calls, tainted input to sinks | — |

Every finding is tagged with OWASP Top 10 (2021) and OWASP LLM Top 10 (2025) classifications in SARIF output.

---

## Installation

Install from PyPI:

```
pip install secchecker
```

Requires Python 3.8 or later. No external dependencies.

---

## How to use it

secchecker accepts a file or directory path and optional flags. Run `secchecker --help` for the full reference.

**Scan a project for secrets:**

```
secchecker .
```

**Scan for LLM/AI vulnerabilities:**

```
secchecker . --type llm
```

**Scan infrastructure configs — Dockerfile, Terraform, Kubernetes:**

```
secchecker . --type devsecops
```

**Run all scanners together:**

```
secchecker . --type all
```

**Filter findings by severity and write a SARIF report:**

```
secchecker . --type all --severity-threshold HIGH --format sarif --output report.sarif
```

**Available flags:**

| Flag | Values | Default |
|------|--------|---------|
| `--type` | `secrets`, `llm`, `devsecops`, `all` | `secrets` |
| `--format` | `json`, `md`, `xml`, `sarif`, `html` | `md` |
| `--output` / `-o` | file path | `secchecker_report.<format>` |
| `--severity-threshold` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | — |
| `--config` | path to `.secchecker.yml` | auto-detected |
| `--no-entropy` | — | entropy enabled |
| `--verbose` / `-v` | — | — |

**Exit codes:** `0` — no findings at or above threshold. `1` — findings detected. `2` — runtime error.

---

## What gets detected

### Secrets — 52+ patterns across 15 credential categories

| Category | Examples | Severity |
|----------|----------|----------|
| Private keys | RSA, EC, DSA, PGP, SSH | CRITICAL |
| Financial | Credit cards (Luhn-validated), SSN | CRITICAL |
| Vault tokens | HashiCorp Vault | CRITICAL |
| Cloud keys | AWS, Google Cloud, Azure | HIGH |
| Database URIs | PostgreSQL, MySQL, MongoDB, Redis | HIGH |
| Service tokens | Stripe, Twilio, SendGrid, Datadog | HIGH |
| VCS tokens | GitHub, GitLab | HIGH |
| Auth tokens | JWT (structure-validated), Bearer | MEDIUM |
| Config passwords | Common password assignment patterns | MEDIUM |

Matches are validated post-regex — credit cards pass the Luhn algorithm, JWT tokens are verified for structural integrity — to reduce false positives.

### LLM / AI security — 18+ patterns, tagged OWASP LLM Top 10 (2025)

| Risk | What it catches | OWASP LLM | Severity |
|------|----------------|-----------|----------|
| Prompt injection | User input concatenated directly into LLM prompt strings | LLM01:2025 | HIGH |
| Jailbreak literals | Hardcoded override instructions in source | LLM01:2025 | HIGH |
| RAG data leakage | Unfiltered database queries or file reads fed into model context | LLM08:2025 | HIGH |
| Insecure output handling | Model response passed directly to eval or exec | LLM05:2025 | CRITICAL |
| AI API key exposure | OpenAI, Anthropic, HuggingFace, Pinecone keys in source | LLM02:2025 | CRITICAL |
| Sensitive data in prompt | PII or financial data concatenated into prompt strings | LLM02:2025 | CRITICAL |
| System prompt disclosure | Hardcoded system prompts revealing application logic | LLM07:2025 | LOW |

### DevSecOps — 28+ patterns, tagged OWASP Top 10 (2021)

| Category | Risk examples | Severity |
|----------|--------------|----------|
| Dockerfile | Unpinned base images, secrets in ENV, curl-pipe-bash, root user | HIGH |
| Kubernetes | Privileged containers, hostNetwork, allow privilege escalation | CRITICAL |
| Terraform | Open security groups (0.0.0.0/0), public S3 buckets, plaintext credentials | HIGH |
| CI/CD | Secrets echoed to logs, pull_request_target misuse, unpinned actions | HIGH |

---

## Output formats

secchecker writes results in five formats, selectable with `--format`:

| Format | Use case |
|--------|----------|
| **Markdown** | Human-readable reports, pull request comments |
| **JSON** | Programmatic consumption, custom dashboards |
| **SARIF 2.1.0** | GitHub Security tab, IDE integrations, OWASP/CWE tags included |
| **HTML** | Self-contained audit reports for sharing with stakeholders |
| **XML** | Legacy toolchain integration |

SARIF output includes OWASP Top 10 2021 categories, OWASP LLM Top 10 2025 categories, and CWE IDs on every rule — compatible with the GitHub Security tab without additional configuration.

---

## Architecture

### Component overview

```
                        ┌─────────────────────────────────────────┐
                        │              cli.py  (main)              │
                        │  --type  --format  --severity-threshold  │
                        │  --config  --no-entropy  --output        │
                        └──────────────┬──────────────────────────┘
                                       │ orchestrates
              ┌────────────────────────┼────────────────────────┐
              ▼                        ▼                         ▼
   ┌──────────────────┐   ┌───────────────────────┐   ┌─────────────────────┐
   │  core.py         │   │  llm_scanner.py        │   │ devsecops_scanner.py│
   │  secrets scanner │   │  LLM/AI vuln scanner   │   │ infra config scanner│
   │  patterns.py     │   │  llm_patterns.py        │   │ devsecops_patterns  │
   └──────────────────┘   └───────────────────────┘   └─────────────────────┘
              │                        │                         │
              └────────────────────────┼─────────────────────────┘
                                       │ entropy.py (optional, overlaid)
                                       │
                        ┌──────────────▼──────────────────────────┐
                        │   Dict[filepath, Dict[pattern, matches]] │
                        │          shared result contract          │
                        └──────────────┬──────────────────────────┘
                                       │ passed to one reporter
        ┌──────────┬───────────────────┼──────────────┬──────────────┐
        ▼          ▼                   ▼               ▼              ▼
    reporter.py  reporter.py       reporter.py   sarif_reporter  html_reporter
      to_json()  to_markdown()     to_xml()      to_sarif()      to_html()
```

### Module map

| Module | Role | Key exports |
|--------|------|-------------|
| `cli.py` | Entry point, orchestration | `main()` |
| `core.py` | Secrets scanner + file filtering | `scan_file()`, `scan_directory()`, `should_skip_file()`, `should_skip_directory()` |
| `patterns.py` | 52+ secret regexes | `PATTERNS` |
| `llm_scanner.py` | LLM/AI vulnerability scanner | `scan_file_llm()`, `scan_directory_llm()` |
| `llm_patterns.py` | 18+ LLM/AI regexes | `LLM_PATTERNS`, `LLM_SEVERITY_MAP` |
| `devsecops_scanner.py` | Infra config scanner | `scan_file_devsecops()`, `scan_directory_devsecops()` |
| `devsecops_patterns.py` | 28+ infra regexes | `DEVSECOPS_PATTERNS`, `FILE_TYPE_FILTER` |
| `entropy.py` | Shannon entropy detection | `scan_file_entropy()`, `shannon_entropy()` |
| `ast_scanner.py` | Python AST structural analysis | `scan_file_ast()`, `scan_directory_ast()` |
| `validators.py` | Post-match false-positive reduction | `validate_match()`, `luhn_check()`, `is_valid_jwt()` |
| `owasp.py` | OWASP Top 10 / LLM Top 10 / CWE mapping | `get_owasp()` |
| `reporter.py` | JSON / Markdown / XML output | `to_json()`, `to_markdown()`, `to_xml()`, `get_severity()` |
| `sarif_reporter.py` | SARIF 2.1.0 output | `to_sarif()`, `generate_sarif_report()` |
| `html_reporter.py` | Self-contained HTML output | `to_html()`, `generate_html_report()` |
| `config.py` | `.secchecker.yml` loader | `load_config()`, `find_config_file()` |

### Severity pipeline

Every finding flows through a single severity pipeline regardless of which scanner produced it:

```
Pattern definition          SEVERITY_MAP / LLM_SEVERITY_MAP / DEVSECOPS_SEVERITY_MAP
        |                           |
        +-------- get_severity() ---+
                       |
               CLI --severity-threshold     <- filter here before reporting
                       |
               Reporter (color / SARIF level / HTML badge)
```

SARIF level mapping: `CRITICAL` and `HIGH` map to `error`. `MEDIUM` maps to `warning`. `LOW` maps to `note`.

### Design principles

- Zero runtime dependencies — stdlib only, no pip install chain to audit
- Python 3.8–3.12 compatible, tested in CI across all versions
- All scanners share a single file-filtering contract via `core.py` — no scanner walks files independently
- Config loading never raises — returns safe defaults on any parse error
- Reporters are pure functions: identical input always produces identical output
- Post-match validators (Luhn, JWT structure) reduce false positives before results are returned

---

## Real-world scenarios

### Scenario 1: Block secrets from reaching CI

A team uses secchecker as a pre-commit gate. Any commit that introduces a secret pattern at severity HIGH or above is rejected before it leaves the developer's machine. SARIF output is also uploaded to the GitHub Security tab on every pull request, giving security teams visibility without blocking developers.

### Scenario 2: Audit an LLM-powered application

A FastAPI service wrapping OpenAI is scanned with the LLM scanner before each release. The scanner surfaces prompt strings that concatenate user input without sanitisation, database query results passed directly into model context, and eval calls against model responses — all common patterns in early-stage AI applications that create exploitable injection paths.

### Scenario 3: Harden infrastructure before deployment

Infrastructure code for a Kubernetes-hosted service is scanned with the DevSecOps scanner as part of a Terraform plan stage. The scan catches open security groups, privileged container specs, and CI pipeline steps that echo secrets to logs — before the configuration reaches a production cluster.

### Scenario 4: Continuous monitoring in CI/CD

secchecker runs on every push via GitHub Actions. SARIF results are uploaded directly to the repository's Security tab. Findings at CRITICAL severity fail the build. HIGH findings create annotations on the pull request diff. The team treats the Security tab as their primary finding triage surface.

---

## GitHub Action

secchecker ships as a composite GitHub Action. Add it to any workflow:

```yaml
- uses: vishnu-77/secchecker@v0.3.0
  with:
    path: '.'
    type: 'all'
    format: 'sarif'
    severity-threshold: 'LOW'
    fail-on-findings: 'true'
```

SARIF output is automatically uploaded to the GitHub Security tab.

**Action inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory or file to scan |
| `type` | `secrets` | Scan type: `secrets`, `llm`, `devsecops`, `all` |
| `format` | `sarif` | Output format |
| `severity-threshold` | `LOW` | Minimum severity to report |
| `output` | `secchecker_report.sarif` | Output file path |
| `fail-on-findings` | `true` | Fail the workflow if findings are detected |

---

## Configuration

Create `.secchecker.yml` in your project root to control scan behaviour without passing flags each time:

```yaml
severity_threshold: MEDIUM
exclude_paths:
  - "tests/"
  - "*.mock.*"
  - "node_modules/"
scan_types:
  - secrets
  - llm
entropy:
  enabled: true
  threshold: 4.5
custom_patterns:
  "Internal API Key": "myco_[a-zA-Z0-9]{32}"
```

CLI flags take precedence over the config file.

---

## Python library

secchecker is also importable as a Python library. All scanners are available as functions that accept a file or directory path and return a consistent result structure. All reporters accept that structure and write to a file or return a string.

The shared result type is `Dict[filepath, Dict[pattern_name, List[matched_strings]]]`. Scanners can be run individually or composed — the CLI merges results from all active scanners before passing them to the selected reporter.

Available scanner functions: `scan_file`, `scan_directory` (secrets), `scan_file_llm`, `scan_directory_llm`, `scan_file_devsecops`, `scan_directory_devsecops`, `scan_file_ast`, `scan_directory_ast`, `scan_file_entropy`.

Available reporter functions: `to_json`, `to_markdown`, `to_xml`, `to_sarif`, `to_html`.

---

## Metrics

- **52+ secret patterns** across 15 credential categories
- **18+ LLM/AI vulnerability checks** — the only PyPI static scanner with a dedicated AI security layer
- **28+ DevSecOps checks** across Dockerfile, Kubernetes, Terraform, and CI/CD configs
- **AST-based Python analysis** — structural detection beyond regex, covering hardcoded assignments, eval/exec, and taint flows
- **OWASP Top 10 (2021) + OWASP LLM Top 10 (2025)** tags on every SARIF rule
- **Post-match validation** — Luhn algorithm for credit cards, JWT structural check — to reduce noise
- **5 output formats**: JSON, Markdown, XML, SARIF 2.1.0, HTML
- **Python 3.8–3.12** compatibility tested in CI across all supported versions
- **Zero runtime dependencies** — installs anywhere Python runs, no transitive supply chain risk

---

## Comparison

| Capability | secchecker | Bandit | detect-secrets | Gitleaks | Checkov |
|-----------|-----------|--------|----------------|----------|---------|
| Secret detection | Yes | Partial¹ | Yes | Yes | Partial² |
| LLM / AI security | Yes | No | No | No | No |
| Dockerfile / K8s / Terraform | Yes | No | No | No | Yes |
| AST-based Python analysis | Yes | Yes | No | No | No |
| Shannon entropy detection | Yes | No | Yes | Yes | Partial³ |
| SARIF output | Yes | Yes | No | Yes | Yes |
| OWASP LLM Top 10 tags | Yes | No | No | No | No |
| Zero runtime dependencies | Yes | No | No | No | No |

¹ Bandit detects hardcoded password assignments (B105–B107) but not API keys, cloud credentials, or service tokens.
² Checkov's secret detection targets IaC files; coverage of general source code secrets is limited.
³ Checkov's entropy detection (CKV_SECRET_6) applies to IaC files only.

---

## Contributing

Clone the repository, install in editable mode with dev dependencies, and run the test suite:

```
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e ".[dev]"
pytest tests/ -v
```

**To add a new secret pattern:** add the regex to `secchecker/patterns.py`, add a severity entry to `SEVERITY_MAP` in `secchecker/reporter.py`, and add OWASP/CWE mappings to `secchecker/owasp.py`. Include a test in `tests/test_patterns.py`.

**To add a new LLM check:** add the pattern to `secchecker/llm_patterns.py` and a severity entry to `LLM_SEVERITY_MAP`. Include a test in `tests/test_llm_scanner.py`.

Pull requests are welcome. Keep changes focused and include tests for new patterns or behaviour.

---

## Pre-commit integration

secchecker ships a `.pre-commit-hooks.yaml` so it can be used directly with the [pre-commit framework](https://pre-commit.com). Add the following to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/vishnu-77/secchecker
    rev: v0.3.0
    hooks:
      - id: secchecker          # secret detection only
      # - id: secchecker-llm    # LLM/AI security only
      # - id: secchecker-all    # all scanners
```

Three hooks are available: `secchecker` (secrets), `secchecker-llm` (LLM/AI patterns), and `secchecker-all` (full audit). All default to failing on HIGH and above.

---

## Roadmap

The following capabilities are planned for upcoming releases:

| Feature | Description | Release target |
|---------|-------------|----------------|
| Incremental scan / cache | Hash-based file cache so only changed files are re-scanned — critical for large monorepos | 0.4.0 |
| Baseline file | `.secchecker-baseline.json` to record accepted findings and suppress them on future runs | 0.4.0 |
| `--diff` mode | Accept git diff on stdin and scan only changed lines — faster pre-push hook | 0.4.0 |
| Custom rule DSL | Per-rule severity, description, and enable/disable in `.secchecker.yml` | 0.4.0 |
| Deeper taint analysis | Track taint through function arguments, return values, and dict assignments in the AST scanner | 0.5.0 |
| VS Code integration | Document SARIF viewer compatibility; evaluate a minimal diagnostic extension | 0.5.0 |

---

## Responsible use

secchecker is intended for security auditing of repositories you own or have explicit written permission to test. It is not a substitute for a full penetration test or security audit. The author assumes no liability for misuse.

If you find a security vulnerability in secchecker itself, see [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## License

MIT — see [LICENSE](LICENSE).
