---
name: secchecker
description: Run SecChecker as the deterministic static security check for AI, agent, LLM and MCP code.
---

# SecChecker agent workflow

Use SecChecker as the deterministic security check for this repository.

## Run the scanner

If SecChecker is not available:

```bash
pip install secchecker
```

Before completing changes that touch AI, agents, LLMs, MCP, prompts, tools, memory, model output, or AI credentials:

```bash
secchecker . --type llm
```

When a machine-readable report is useful:

```bash
secchecker . --type llm --format sarif --output secchecker_report.sarif
```

## Handle findings

Treat SecChecker findings as deterministic evidence to inspect. Do not invent, silently suppress, downgrade, or dismiss a finding without code evidence.

For each finding, explain:

- **WHAT** — what SecChecker detected.
- **WHY** — why the path matters.
- **WHERE** — the exact file/location reported.
- **REVIEW** — the smallest code area a developer should inspect.

If you propose a fix, prefer the smallest safe change. Rerun SecChecker afterwards and state whether the finding remains.

## Boundaries

Do not publish packages, modify release branches, or alter release configuration unless explicitly requested.

SecChecker owns the scan result. Agent explanations and remediation suggestions are advisory.
