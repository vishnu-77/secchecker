[![PyPI version](https://img.shields.io/pypi/v/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Python versions](https://img.shields.io/pypi/pyversions/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Downloads](https://img.shields.io/pypi/dm/secchecker.svg)](https://pypi.org/project/secchecker/)
[![Build Status](https://github.com/vishnu-77/secchecker/actions/workflows/ci.yml/badge.svg)](https://github.com/vishnu-77/secchecker/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![codecov](https://codecov.io/gh/vishnu-77/secchecker/branch/main/graph/badge.svg)](https://codecov.io/gh/vishnu-77/secchecker)

# secchecker

**Static security scanner for AI agents, MCP tools, and LLM applications.**
Catches prompt injection, MCP tool poisoning, and agentic vulnerabilities before
deployment — plus source-code secrets and infrastructure-as-code, in the same pass.
Zero dependencies, runs anywhere Python runs.

## Install

```
pip install secchecker
```

Python 3.8+, no external dependencies.

## Use

```
secchecker . --type llm       # AI agent / LLM / MCP vulnerabilities (recommended)
secchecker . --type secrets   # hardcoded credentials only
secchecker . --type devsecops # Dockerfile, Terraform, Kubernetes, CI/CD
secchecker . --type all       # everything, one pass

secchecker . --type all --severity-threshold HIGH --format sarif --output report.sarif
```

| Flag | Values | Default |
|---|---|---|
| `--type` | `secrets`, `llm`, `devsecops`, `all` | `secrets` |
| `--format` | `json`, `md`, `xml`, `sarif`, `html` | `md` |
| `--output` / `-o` | file path | `secchecker_report.<format>` |
| `--severity-threshold` | `LOW`…`CRITICAL` | — |
| `--config` | path to `.secchecker.yml` | auto-detected |

Exit codes: `0` clean · `1` findings at/above threshold · `2` runtime error.

## What it catches

| Scanner | Detects | Patterns |
|---|---|---|
| LLM / AI | Prompt injection, RAG leakage, eval of model output, hardcoded AI API keys | 18+ |
| MCP / Agentic | Tool poisoning, tool-output execution, memory injection, PII to external agents | 9 |
| Secrets | Cloud keys, private keys, database URIs, payment credentials, service tokens | 52+ |
| DevSecOps | Dockerfile, Kubernetes, Terraform, CI/CD misconfigurations | 28+ |
| Entropy | Unknown secrets by Shannon entropy — catches what regex misses | — |
| AST | Hardcoded secrets, eval/exec calls, tainted input to sinks (Python) | — |

Every finding is tagged OWASP Top 10 (2021) / OWASP LLM Top 10 (2025) in SARIF
output — for developer guidance, not a certification or compliance claim.
Matches are post-validated (Luhn for cards, structural checks for JWTs) to cut
false positives.

## Output formats

Markdown (PR comments), JSON (dashboards), **SARIF 2.1.0** (GitHub Security tab,
IDE integrations — OWASP/CWE tags included), HTML (shareable reports), XML.

## GitHub Action

```yaml
- uses: vishnu-77/secchecker@v0.4.0
  with:
    path: '.'
    type: 'all'
    format: 'sarif'
    severity-threshold: 'LOW'
    fail-on-findings: 'true'
```

SARIF uploads to the Security tab automatically.

## Pre-commit

```yaml
repos:
  - repo: https://github.com/vishnu-77/secchecker
    rev: v0.4.0
    hooks:
      - id: secchecker          # secrets only
      # - id: secchecker-llm    # LLM/AI only
      # - id: secchecker-all    # everything
```

## Config

`.secchecker.yml` in your project root:

```yaml
severity_threshold: MEDIUM
exclude_paths: ["tests/", "*.mock.*", "node_modules/"]
scan_types: [secrets, llm]
entropy: { enabled: true, threshold: 4.5 }
custom_patterns:
  "Internal API Key": "myco_[a-zA-Z0-9]{32}"
```

CLI flags override the config file.

Also usable as a Python library (every scanner/reporter is importable
directly) — module map and internals: [ARCHITECTURE.md](ARCHITECTURE.md).

## Contributing

```
git clone https://github.com/vishnu-77/secchecker.git
cd secchecker && pip install -e ".[dev]" && pytest tests/ -v
```

New pattern → add the regex + a severity entry + a test (`patterns.py` /
`llm_patterns.py`, `reporter.py`, `tests/`). See [CONTRIBUTING.md](CONTRIBUTING.md).
Roadmap and history: [CHANGELOG.md](CHANGELOG.md).

## Responsible use

For repositories you own or have explicit permission to test — not a substitute
for a full security audit. Found a vulnerability in secchecker itself? See
[SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
