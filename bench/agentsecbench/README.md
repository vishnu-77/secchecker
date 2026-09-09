# AgentSecBench (real-world corpus)

`bench/fixtures/` is self-authored: paired vulnerable/safe files written by the same
person who wrote the detector, scored 1.00/1.00, and explicitly documented in
`bench/methodology.md` as *not* an accuracy claim. AgentSecBench is the other half:
secchecker run against **real, unmodified, third-party AI-agent applications**, to see
what it actually catches and misses in code nobody wrote to please the scanner.

Scope: LangGraph, MCP (client + reference servers), OpenAI Agents SDK, Claude/Anthropic
agent integrations, and one hand-rolled multi-tool research agent (custom wrappers, not
a named framework).

See [`SUMMARY.md`](SUMMARY.md) for the findings and what they imply for the roadmap.
Individual reproducible cases are under [`cases/`](cases/), one file each. Raw scanner
JSON output is under `raw_results/` as evidence.

## Corpus

| Repo | Framework | Commit (pinned) | .py files | Findings, first scan | Findings, after fix* |
|---|---|---|---|---|---|
| [langchain-ai/social-media-agent](https://github.com/langchain-ai/social-media-agent) | LangGraph | `61053aa` (2026-09-08) | 7 | 1 | 0 |
| [langchain-ai/langgraph-supervisor-py](https://github.com/langchain-ai/langgraph-supervisor-py) | LangGraph | `88859b3` (2026-07-14) | 8 | 0 | 0 |
| [modelcontextprotocol/servers](https://github.com/modelcontextprotocol/servers) | MCP reference servers | `d73f99e` (2026-09-02) | 14 (+76 TS) | 0 | 0 |
| [openai/openai-agents-python](https://github.com/openai/openai-agents-python) | OpenAI Agents SDK | `83c737f` (2026-09-09) | 945 | 5 | 0 |
| [anthropics/anthropic-cookbook](https://github.com/anthropics/anthropic-cookbook) | Claude / Claude Agent SDK | `a97b9a2` (2026-09-03) | 122 (+notebooks) | 25 | 22 |
| [assafelovic/gpt-researcher](https://github.com/assafelovic/gpt-researcher) | Custom tool wrappers (LangChain-based) | `6f99857` (2026-08-23) | 331 | 24 | 22 |

\* After the context guards in [`SUMMARY.md`](SUMMARY.md) § Fix status. Fewer findings
is the point here, not a regression — every removed finding is a cataloged false
positive (`cases/FP-*.md`); both true positives (`TP-01`, `TP-02`) still fire in the
"after" columns above. Raw JSON for both runs is in `raw_results/` (first scan) and
`raw_results_after_fix/` (current).

All clones are shallow (`--depth 1`) at the commit above. secchecker version under test:
**0.5.0** (`bench/agentsecbench/raw_results/*.json` → `metadata.version`) plus the
context guards landed in this same session (not yet a tagged release).

## Reproducing

```bash
git clone --depth 1 <repo-url> <dest> && git -C <dest> rev-parse HEAD  # confirm pin above
secchecker scan <dest> --type llm --format json -o out.json --severity-threshold LOW
```

No LLM judge, no network calls from secchecker itself — same input reproduces the same
output. Findings were triaged by hand (reading the flagged line in context, not just
the matched keyword) — see each case file for the reasoning, not just the verdict.
