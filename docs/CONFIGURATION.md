# Configuration

## CLI flags

secchecker accepts a file or directory path and optional flags. Run `secchecker --help` for the full reference.

| Flag | Values | Default |
|------|--------|---------|
| `--type` | `secrets`, `llm`, `devsecops`, `all` | `secrets`, or `scan_types` from `.secchecker.yml` if set |
| `--format` | `json`, `md`, `xml`, `sarif`, `html` | `md` |
| `--output` / `-o` | file path | `secchecker_report.<format>` |
| `--severity-threshold` | `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` | — |
| `--config` | path to `.secchecker.yml` | auto-detected |
| `--no-entropy` | — | entropy only runs if enabled in config; this flag force-disables it |
| `--pii` | — | opt-in Email/Phone Number detection, off by default |
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
exclude_patterns:
  - "Email"
  - "LLM - *"
scan_types:
  - secrets
  - llm
entropy:
  enabled: true
  threshold: 4.5
  min_length: 20
custom_patterns:
  "Internal API Key": "myco_[a-zA-Z0-9]{32}"
```

CLI flags take precedence over the config file. Config loading never raises — it returns safe defaults on any parse error.

| Key | Behavior |
|-----|----------|
| `severity_threshold` | Minimum severity to report; same effect as `--severity-threshold`. |
| `exclude_paths` | File/directory exclusions — glob (`*.mock.*`), path component (`node_modules`), directory prefix (`tests/`), or multi-segment literal. Applied after all scanners run. |
| `exclude_patterns` | Finding-*category* (rule name) exclusions — case-insensitive fnmatch globs, e.g. `"Email"` or `"LLM - *"`. Distinct from `exclude_paths`: this drops specific rule names wherever they fire, not files. |
| `scan_types` | Default scan type(s) when `--type` is not passed on the command line. `--type` always overrides this. |
| `entropy.enabled` / `.threshold` / `.min_length` | Entropy scanning is opt-in — set `enabled: true` to turn it on. `--no-entropy` force-disables it regardless of this setting. |
| `custom_patterns` | Additional `{name: regex}` patterns merged into the secrets scan (`--type secrets`/`all`). Custom pattern names default to `LOW` severity unless also added to `SEVERITY_MAP`. |
