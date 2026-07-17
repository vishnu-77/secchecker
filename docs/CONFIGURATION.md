# Configuration

## CLI flags

secchecker accepts a file or directory path and optional flags. Run `secchecker --help` for the full reference.

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

## Config file: `.secchecker.yml`

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

CLI flags take precedence over the config file. Config loading never raises — it returns safe defaults on any parse error.
