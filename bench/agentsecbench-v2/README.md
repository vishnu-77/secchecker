# AgentSecBench v2

Benchmark-only branch for SecChecker's LLM/MCP/agentic scanner.

## Invariants

- Scanner implementation is unchanged from `main` at `17f6b8ffb3a7e8c03fb3cb0cd104b23870201bc3`.
- Scanner code baseline remains `f2137be1bc95f969cc2211c7680d4822e4c69902`.
- No package-version changes.
- No rule, severity, CLI, reporter, scanner, or configuration changes.
- Target repositories are scanned unmodified at frozen commit SHAs.
- First-pass results are collected before any tuning.
- Raw findings are not treated as vulnerabilities until triaged.

## Corpus

The frozen corpus is defined in `manifest.json` and covers:

- browser agents
- typed agent frameworks
- memory/tool orchestration
- multi-agent systems
- Python MCP servers/clients
- a real MCP coordination application

## Run

```bash
python bench/agentsecbench-v2/run.py
python bench/agentsecbench-v2/summarize.py
```

The automated workflow performs the same run in GitHub Actions and commits only benchmark results back to this benchmark branch.

## Outputs

```text
results/
  raw/*.json       raw SecChecker reports
  scan_meta.tsv    pinned SHA, runtime, scanner exit code
  summary.json     machine-readable first-pass summary
  SUMMARY.md       human-readable first-pass summary
  triage.csv       empty TP / FP / UNCERTAIN review ledger
```

Precision and recall are intentionally not computed in the first pass. They are calculated only after findings and false-negative review are independently labelled.
