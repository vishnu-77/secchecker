# AgentSecBench v2 — raw first-pass summary

This table is scanner output only. It is **not** an accuracy score. Findings must be triaged before precision is calculated, and false negatives require targeted review.

| Repository | Files with findings | Matches | Critical | High | Medium | Low | Seconds | Exit |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| browser-use/browser-use | 79 | 87 | 4 | 81 | 2 | 0 | 7.03 | 1 |
| pydantic/pydantic-ai | 8 | 8 | 0 | 6 | 0 | 2 | 210.31 | 1 |
| agno-agi/agno | 31 | 40 | 0 | 40 | 0 | 0 | 65.84 | 1 |
| camel-ai/camel | 27 | 27 | 1 | 25 | 1 | 0 | 52.53 | 1 |
| PrefectHQ/fastmcp | 3 | 3 | 0 | 3 | 0 | 0 | 13.55 | 1 |
| Dicklesworthstone/mcp_agent_mail | 0 | 0 | 0 | 0 | 0 | 0 | 5.80 | 0 |

## Scoring discipline

- Do not change SecChecker while first-pass results are being collected or triaged.
- A scanner finding is not automatically a true positive.
- Record TP / FP / UNCERTAIN in the triage ledger with code evidence.
- Record false negatives separately during targeted framework/trust-boundary review.
- Only compute precision/recall after the labels are frozen.
