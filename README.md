[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Downloads](https://img.shields.io/pypi/dm/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![codecov](https://codecov.io/gh/vishnu-77/secchecker/branch/main/graph/badge.svg)](https://codecov.io/gh/vishnu-77/secchecker)

# secchecker

**Lightweight security auditing for DevSecOps and AI systems.**

secchecker is a zero-dependency CLI tool and Python library that detects hardcoded secrets, LLM/AI vulnerabilities, and infrastructure misconfigurations in source code. Think Bandit + Checkov — with an AI security layer no other PyPI tool has.

```bash
pip install secchecker
secchecker . --type all --format sarif --output report.sarif
```

---

## Why secchecker

Most static scanners stop at secrets. secchecker goes further:

- **52+ secret patterns** — cloud keys, private keys, database URIs, payment credentials, service tokens
- **18+ LLM/AI checks** — prompt injection via f-strings, jailbreak literals, RAG data leakage, `eval(llm_response)`, hardcoded AI API keys
- **28+ DevSecOps checks** — Dockerfile, Kubernetes YAML, Terraform, CI/CD pipeline misconfigurations
- **Entropy detection** — catches unknown secrets that don't match any known pattern
- **5 output formats** — JSON, Markdown, XML, SARIF (GitHub Security tab), HTML
- **Zero dependencies** — stdlib only, works anywhere Python runs

---

## Architecture

```
secchecker
├── Scanners
│   ├── secrets      (patterns.py)       40+ hardcoded secret regexes
│   ├── llm          (llm_scanner.py)    18+ LLM/AI vulnerability patterns
│   ├── devsecops    (devsecops_scanner) 28+ infra misconfiguration patterns
│   └── entropy      (entropy.py)        Shannon entropy for unknown secrets
│
├── Reporters
│   ├── JSON   sarif   XML   Markdown   HTML
│   └── Severity: CRITICAL / HIGH / MEDIUM / LOW
│
└── Config  (.secchecker.yml)  exclude paths, custom patterns, thresholds
```

All scanners return the same shape: `Dict[filepath, Dict[pattern_name, List[str]]]`.

---

## Installation

```bash
pip install secchecker
```

Requires Python 3.8+. No external dependencies.

---

## Usage

### Scan for secrets (default)

```bash
secchecker .
secchecker /path/to/project --format json --output report.json
secchecker src/config.py --severity-threshold HIGH
```

### Scan for LLM/AI vulnerabilities

```bash
secchecker . --type llm
secchecker . --type llm --format html --output llm_report.html
```

### Scan infrastructure configs (Dockerfile, Terraform, K8s)

```bash
secchecker . --type devsecops --format sarif --output report.sarif
```

### Run all scanners at once

```bash
secchecker . --type all --format sarif --output report.sarif
```

### Filter by severity

```bash
# Only report HIGH and CRITICAL findings
secchecker . --severity-threshold HIGH
```

### All options

```
secchecker PATH [options]

  --type {secrets,llm,devsecops,all}   Scan type (default: secrets)
  --format {json,md,xml,sarif,html}    Output format (default: md)
  --output, -o FILE                    Output file path
  --severity-threshold LEVEL           Minimum severity: LOW/MEDIUM/HIGH/CRITICAL
  --config FILE                        Path to .secchecker.yml
  --no-entropy                         Disable entropy-based detection
  --verbose, -v                        Verbose output

Exit codes:
  0  No findings at or above threshold
  1  Findings detected
  2  Runtime error
```

---

## What gets detected

### Secrets (52+ patterns)

| Category | Examples | Severity |
|----------|----------|----------|
| Private keys | RSA, EC, DSA, PGP, SSH | CRITICAL |
| Financial | Credit cards, SSN | CRITICAL |
| Vault tokens | HashiCorp Vault `hvs.*` | CRITICAL |
| Cloud keys | AWS, Google, Azure | HIGH |
| Database URIs | PostgreSQL, MySQL, MongoDB | HIGH |
| Service tokens | Stripe, Twilio, SendGrid, Datadog | HIGH |
| VCS tokens | GitHub, GitLab | HIGH |
| Auth tokens | JWT, Bearer, Basic Auth | MEDIUM |
| Config passwords | `password=`, `db_pass=` | MEDIUM |

### LLM / AI security (18+ patterns)

| Check | What it catches | Severity |
|-------|----------------|----------|
| Prompt injection | `f"...{user_input}..."` in LLM calls | HIGH |
| Jailbreak literals | Hardcoded "ignore previous instructions" strings | HIGH |
| RAG leakage | Unfiltered DB query / file read fed into LLM context | HIGH |
| Output execution | `eval(llm_response)`, `exec(response)` | CRITICAL |
| AI API key exposure | OpenAI `sk-...`, Anthropic `sk-ant-...`, HuggingFace tokens | CRITICAL |
| Sensitive data in prompt | SSN / credit card concatenated into prompt string | CRITICAL |

### DevSecOps (28+ patterns)

| Category | Examples | Severity |
|----------|----------|----------|
| Dockerfile | `FROM *:latest`, secret in `ENV`, `curl \| sh`, `COPY . .` | HIGH |
| Kubernetes | `privileged: true`, `runAsUser: 0`, `hostNetwork: true` | CRITICAL |
| Terraform | Open security group `0.0.0.0/0`, public S3 bucket, hardcoded creds | HIGH |
| CI/CD | Secret echoed to log, `pull_request_target` abuse, unpinned actions | HIGH |

---

## GitHub Action

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

**Inputs:**

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory or file to scan |
| `type` | `secrets` | Scan type: `secrets`, `llm`, `devsecops`, `all` |
| `format` | `sarif` | Output format |
| `severity-threshold` | `LOW` | Minimum severity to report |
| `output` | `secchecker_report.sarif` | Output file path |
| `fail-on-findings` | `true` | Fail the workflow if findings are detected |

---

## Configuration file

Create `.secchecker.yml` in your project root:

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

---

## Python API

```python
from secchecker import scan_directory, scan_file
from secchecker.reporter import to_json, to_sarif

# Scan a directory
results = scan_directory("/path/to/project")

# Scan a single file
findings = scan_file("/path/to/config.py")

# LLM vulnerability scan
from secchecker.llm_scanner import scan_directory_llm
llm_results = scan_directory_llm("/path/to/ai_app")

# DevSecOps scan
from secchecker.devsecops_scanner import scan_directory_devsecops
infra_results = scan_directory_devsecops("/path/to/infra")

# Generate reports
to_json(results, "report.json")
to_sarif(results, "report.sarif")
```

---

## Real-world use cases

**Use case 1: Pre-commit secret scan**

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secchecker
        name: secchecker
        entry: secchecker
        args: ['.', '--severity-threshold', 'HIGH', '--format', 'md']
        language: system
```

**Use case 2: CI/CD pipeline with SARIF**

```yaml
- name: Security audit
  run: |
    pip install secchecker
    secchecker . --type all --format sarif --output results.sarif
- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

**Use case 3: LLM application review**

```bash
# Scan a FastAPI app that uses OpenAI
secchecker ./app --type llm --severity-threshold HIGH --format html --output llm_audit.html
```

---

## Metrics

- **52+ secret patterns** across 15 credential categories
- **18+ LLM/AI vulnerability checks** — the only PyPI static scanner in this category
- **28+ DevSecOps checks** across Dockerfile, Kubernetes, Terraform, and CI/CD
- **5 output formats**: JSON, Markdown, XML, SARIF, HTML
- **Python 3.8–3.12** compatibility tested in CI
- **Zero runtime dependencies**

---

## Contributing

```bash
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker
pip install -e ".[dev]"
pytest tests/ -v
```

To add new patterns:

1. Add the regex to `secchecker/patterns.py` (secrets) or the relevant `*_patterns.py`
2. Add a severity entry to `SEVERITY_MAP` in `secchecker/reporter.py`
3. Add a test in `tests/test_patterns.py`

Pull requests are welcome. Please keep changes focused and include tests.

---

## Disclaimer

secchecker is intended for security auditing of repositories you own or have explicit permission to test. The author assumes no liability for misuse. Use responsibly.

## License

MIT — see [LICENSE](LICENSE).
