# AgentSecBench — real-world stress test results

secchecker 0.5.0's `--type llm` scanner, run against 6 real open-source AI-agent repos
(LangGraph, MCP, OpenAI Agents SDK, Claude/Anthropic integrations, custom tool
wrappers), 2026-09-09. See `README.md` for the pinned corpus and `cases/` for the
individual reproducible write-ups this summary draws from.

## Headline numbers

| | Count |
|---|---|
| Repos scanned | 6 |
| Total findings | 46 (across 4 repos with any findings; 2 repos scanned clean) |
| Manually triaged | 12 findings + 2 whole-repo coverage checks |
| True positives | 2 (1 correctly labeled, 1 real but mislabeled category) |
| False positives | 8 |
| Coverage gaps (structural, not a single bad match) | 2 |

**Precision on the triaged sample as first scanned: 2/10 labeled findings (20%).** This
is a small, hand-triaged sample from 4 repos — not a statistically powered number — but
it's a sharp contrast with `bench/fixtures`' self-authored 1.00/1.00, and it's the
number this exercise exists to surface: **on code nobody wrote to please the scanner,
most HIGH/CRITICAL findings in this sample were false positives**, concentrated in one
root cause. After the fix below, re-running the same corpus: 2 of the 6 repos scan
completely clean where they previously had findings, and 6 of the 8 cataloged false
positives are gone — see "Fix status."

## The dominant failure mode: lexical co-occurrence, not data flow

7 of 8 false positives ([FP-01](cases/FP-01-anthropic-docs-json-rag-corpus.md),
[02](cases/FP-02-name-vs-value-confusion.md), [03](cases/FP-03-mcp-poisoned-docstring-on-non-mcp-function.md),
[04](cases/FP-04-server-url-identifier-name-coincidence.md),
[05](cases/FP-05-security-control-flagged-as-the-violation.md),
[06](cases/FP-06-demo-phrase-secret-word.md), [07](cases/FP-07-typescript-field-declaration.md))
share one root cause: the LLM/agentic rules key on **keywords appearing near each
other** (`secret`/`credential`/`token`/`server_url`/`system:` near
`message`/`prompt`/`context`), not on an actual value flowing into an actual LLM call.
Concretely, this pattern fires equally on:

- documentation *about* API keys (FP-01) as on an API key itself,
- printing an env var's *name* (FP-02) as on printing its *value*,
- a docstring parameter literally named `system` (FP-03) as on an instruction-override
  payload,
- any `server_url` identifier (FP-04) as on an actual MCP client configuration,
- the code that **redacts credentials from the LLM sandbox** (FP-05) as on code that
  leaks them to it — the sharpest example, since it's the exact inverse of the real
  risk,
- the English word "secret" in a toy tool's name (FP-06),
- a TypeScript field declaration with no LLM call anywhere nearby (FP-07).

**The fix implied by all seven cases is the same and is narrow:** require a real sink
(an LLM API call site — `.create(`, `messages.append`, `ChatCompletion`, a known
SDK client method) in the matched window for the `LLM -`/`Agentic -` rules, and gate
`MCP -` rules behind actual MCP import/protocol evidence in the file, rather than
firing on keyword proximity alone. This isn't "rewrite the taint engine" — it's adding
one more condition to checks that already exist.

## What's structurally invisible, not just mismatched

Two whole-repo results didn't produce a single finding, and manual reading showed why:

- **[GAP-01](cases/GAP-01-langgraph-structured-state-invisible.md):**
  `langgraph-supervisor-py`'s entire multi-agent handoff mechanism — an agent's full
  message history propagating to the next agent via `Command`/`Send`/`**state` spreads
  — never touches a string literal, f-string, or `.format()` call. Every existing rule
  is keyed to those idioms, so LangGraph's actual data-flow idiom (typed dict state
  through framework objects) has zero rules that could ever fire on it, regardless of
  precision.
- **[GAP-02](cases/GAP-02-non-python-agent-code-invisible.md):** the official MCP
  reference-servers repo is 84% TypeScript. AST taint tracking is Python-only; even the
  regex layer found nothing in the `.ts` sources, because its trigger vocabulary
  (`os.environ`, f-strings) has no JS/TS equivalent keyed in. secchecker's own
  positioning ("the #1 static scanner for MCP servers") should be read as "for Python
  MCP servers" until this changes.

## What this confirms vs. `docs/ROADMAP.md`

Both gaps land exactly on Phase 3's already-planned "cross-function agentic taint" and
"framework sink packs (LangChain, LlamaIndex, CrewAI, AutoGen, OpenAI-Agents SDK,
FastMCP)" items — this exercise doesn't invalidate that plan, it gives it two concrete,
reproducible repros to build against instead of designing blind. The false-positive
cluster is new information the roadmap didn't have: it's cheaper to fix than the
coverage gaps (a sink-presence check, not a new analysis engine) and arguably higher
priority, since a scanner that's wrong 4 times out of 5 on real code erodes trust in the
1 time it's right.

## Fix status (implemented, measured by re-running this same corpus)

Three small guards landed in `secchecker/llm_scanner.py` — not a new taint engine, one
extra condition per rule, checked against text the rule was already scanning:

1. **LLM-call sink presence** (`_LLM_CALL_SINK_RE`): `LLM - Secret Passed to LLM` now
   requires an actual LLM-call shape (`.create(`, `.invoke(`, `Anthropic(`, `OpenAI(`,
   ...) somewhere in the file.
2. **Value vs. name** (`_VALUE_REF_RE`): `LLM - API Key in Log Statement` now requires
   `os.environ`/`getenv(` or an interpolated `{var}`, not just the key's name as plain
   text.
3. **MCP marker presence** (`_MCP_MARKER_RE`): `MCP - Hardcoded MCP Server URL` now
   requires an MCP import/protocol marker in the file. **Poisoned Tool Docstring** got a
   separate, more targeted fix — an AST check that a `system:` marker match isn't just
   an `Args:` line documenting a real `system` parameter (see FP-03).

**Result, re-running the same six-repo corpus:** `openai-agents-python` and
`social-media-agent` now scan clean (0 findings, were 5 and 1). 6 of the 8 cataloged
false positives are gone — FP-02 (primary case; the `.triage/*.json` recurrences are
not), FP-03, FP-04, FP-05, FP-06, FP-07. Both true positives (TP-01, TP-02) and both
coverage gaps (GAP-01, GAP-02, untouched by this change — different problem) are
unaffected. `bench/run.py`'s synthetic regression corpus stays 1.00/1.00 precision/
recall, and the full test suite (230 tests, 5 new ones added for these guards) passes.

**Not fixed — FP-01 stays open.** `anthropic_docs.json` and the `.triage/*.json` batch
files in `gpt-researcher` are still flagged. Both guards miss here for a structural
reason, not an oversight: `anthropic_docs.json` *is* Anthropic API documentation, so it
genuinely contains real `client.messages.create(...)` example syntax — the sink check
can't tell "docs describing a call" from "code making one." The `.triage/*.json` files
defeat the value-reference guard the opposite way: JSON syntax is brace-dense, so
"a `{` means interpolation" can't distinguish an f-string from ordinary JSON structure.
Fixing this needs a different mechanism — excluding data files (JSON/notebook-as-data)
from these two rules, or requiring the matched value pass an entropy check the way
`secchecker/validators.py` already does for the plain secrets scanner — not just another
proximity condition. See `cases/FP-01-anthropic-docs-json-rag-corpus.md`.

## Remaining next steps

1. FP-01's remaining shape (RAG/data-corpus text) — needs the entropy/data-file
   approach above, not another keyword guard.
2. Treat GAP-01/GAP-02 as the concrete acceptance tests for Phase 3's LangGraph/MCP
   framework packs, not abstract goals — this repo pair is now pinned and reproducible.
3. `MCP - Unvalidated Tool Result in Prompt` / `MCP - Tool Call Output Executed
   Directly` are still mislabeled per TP-02 (real agentic risk, MCP-specific name) —
   left un-gated deliberately, since gating them behind an MCP marker (like the URL
   rule) would silently drop a real finding on non-MCP tool-calling code rather than
   fix the label. Renaming/splitting is a naming decision, not implemented here.
4. Grow this corpus before quoting any precision/recall number externally — 6 repos,
   12 hand-triaged findings is a first pass, not a benchmark with statistical power
   (same caveat `bench/methodology.md` already states for the synthetic corpus, for the
   opposite reason: that one is too easy, this one is too small).
