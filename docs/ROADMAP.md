# Roadmap

**Delivered in 0.4.x:** MCP and agentic AI security patterns, OWASP LLM Top 10 (2025) mappings for the new findings, and the AI/GenAI/MCP-first repositioning.

Planned for upcoming releases:

| Feature | Description | Release target |
|---------|-------------|----------------|
| Deeper taint analysis | Track taint through function arguments, return values, and dict assignments in the AST scanner | 0.5.0 |
| VS Code integration | Document SARIF viewer compatibility; evaluate a minimal diagnostic extension | 0.5.0 |
| Incremental scan / cache | Hash-based file cache so only changed files are re-scanned — critical for large monorepos | 0.6.0 |
| Baseline file | `.secchecker-baseline.json` to record accepted findings and suppress them on future runs | 0.6.0 |
| `--diff` mode | Accept git diff on stdin and scan only changed lines — faster pre-push hook | 0.6.0 |
| Custom rule DSL | Per-rule severity, description, and enable/disable in `.secchecker.yml` | 0.6.0 |
