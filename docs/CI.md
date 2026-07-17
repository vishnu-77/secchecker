# CI integration

## GitHub Action

secchecker ships as a composite GitHub Action. Add it to any workflow:

```yaml
name: secchecker

on:
  pull_request:
  push:
    branches: [main]

jobs:
  secchecker:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: vishnu-77/secchecker@v0.4.2
        with:
          path: '.'
          type: 'all'
          format: 'sarif'
          severity-threshold: 'LOW'
          fail-on-findings: 'true'
```

SARIF output is automatically uploaded to the GitHub Security tab.

### Action inputs

| Input | Default | Description |
|-------|---------|-------------|
| `path` | `.` | Directory or file to scan |
| `type` | `secrets` | Scan type: `secrets`, `llm`, `devsecops`, `all` |
| `format` | `sarif` | Output format |
| `severity-threshold` | `LOW` | Minimum severity to report |
| `output` | `secchecker_report.sarif` | Output file path |
| `fail-on-findings` | `true` | Fail the workflow if findings are detected |

## Pre-commit

secchecker ships a `.pre-commit-hooks.yaml` so it can be used directly with the [pre-commit framework](https://pre-commit.com). Add the following to your `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/vishnu-77/secchecker
    rev: v0.4.2
    hooks:
      - id: secchecker          # secret detection only
      # - id: secchecker-llm    # LLM/AI security only
      # - id: secchecker-all    # all scanners
```

Three hooks are available: `secchecker` (secrets), `secchecker-llm` (LLM/AI patterns), and `secchecker-all` (full audit). All default to failing on HIGH and above.

## Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above threshold |
| `1` | Findings detected |
| `2` | Runtime error |

## Common CI patterns

- **Pre-commit gate** — reject any commit introducing a HIGH+ secret before it leaves the developer's machine; upload SARIF to the Security tab on pull requests for security-team visibility without blocking developers.
- **LLM app release gate** — run `--type llm` before each release of an LLM-backed service to surface prompt concatenation, unfiltered RAG context, and eval of model output.
- **Infra plan stage** — run `--type devsecops` alongside `terraform plan` to catch open security groups, privileged container specs, and pipelines echoing secrets to logs.
- **Continuous monitoring** — run on every push; fail the build on CRITICAL, annotate the PR diff on HIGH, and triage from the Security tab.
