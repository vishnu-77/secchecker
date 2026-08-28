# Output formats

secchecker writes results in five formats, selectable with `--format`:

| Format | Use case |
|--------|----------|
| **Markdown** (`md`) | Human-readable reports, pull request comments (default) |
| **JSON** | Programmatic consumption, custom dashboards |
| **SARIF 2.1.0** | GitHub Security tab, IDE integrations, OWASP/CWE tags included |
| **HTML** | Self-contained audit reports for sharing with stakeholders |
| **XML** | Legacy toolchain integration |

```bash
secchecker . --type all --format sarif --output report.sarif
```

The default output path is `secchecker_report.<format>`; override it with `--output` / `-o`.

## SARIF details

SARIF output includes OWASP Top 10 (2021) categories, OWASP LLM Top 10 (2025) categories, and CWE IDs on every rule — compatible with the GitHub Security tab without additional configuration. Severity-to-level mapping is documented in [OWASP_MAPPING.md](OWASP_MAPPING.md).

## HTML reports

HTML reports are fully self-contained (no external assets), suitable for attaching to audit tickets or sharing with stakeholders. Sample reports are available in [`sample-reports/`](../sample-reports/).
