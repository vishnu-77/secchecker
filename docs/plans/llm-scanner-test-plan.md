# Rigorous test plan — `--type llm` scanner

Scope: the AI / MCP / agent scanner (`secchecker/llm_scanner.py`, 29 regex rules in
`llm_patterns.py`, plus the Python AST checks). Secret, IaC and dependency scanners are out of scope.

Status: draft, 2026-11-14. T1 done (`tests/test_finding_location.py`; G1/G2 fixed). T7 + T8 done
(`tests/test_llm_robustness.py`, no new bugs; G9 config behavior still open). T3 done
(`bench/mutate.py`, `tests/test_mutate_harness.py`; gaps E1–E5 below). T2 done
(`tests/test_rule_matrix.py`; gaps E6–E10 below). T9 done (`tests/test_regression_gate.py`
ratchets against `bench/baseline.json`; runs in the existing CI pytest step). Gaps E1, E3–E10
fixed; E2 fixed for recursive spawning only (the other name-keyed cases need data-flow
analysis). T5 done to first-triage stage (results below; fresh post-fix sample pending).
Remaining: T4 (needs a second, independent labeler), T6 optional.

## Why the current evidence is not enough

| Evidence today | What it proves | What it can't prove |
|---|---|---|
| `bench/fixtures` 23 vulnerable / 23 safe, 1.00 P / 1.00 R | every rule still fires on the case it was written for | accuracy on code nobody wrote to fit the rule |
| `bench/agentsecbench` 6 repos, 12 findings triaged | real code produces mostly false positives (20% precision before fix) | anything with a confidence interval; recall at all |
| Scoring is per file (flagged / not) | a file got *some* finding | the right rule, line and snippet (gap G1/G2 is invisible to it) |

So: no measure of recall on real code, no rule-level numbers, no check that output is correct,
no evasion testing, sample sizes too small to quote.

## Test tracks

Run in this order; each track has a pass bar.

### T1 — Output correctness (do first, cheap)
Every finding must carry the right **rule, file, line and full matched snippet**.
- One golden test per rule (29 regex rules + each AST check): fixture → exact expected
  `(rule, line, snippet)`.
- Covers G1 (`llm_scanner.py:98` returns joined capture groups like `prompt user_input`) and G2
  (SARIF `_line_of()` searches the first occurrence of that fragment).
- **Pass bar:** 100% of golden tests exact-match. Fix G1 before going further — every later
  track relies on findings being locatable.

### T2 — Per-rule matrix
For each rule: ≥3 true positives and ≥3 hard negatives.
- Positives: single-line, multi-line, inside a class/method, async, different quote styles.
- Hard negatives: trigger words in comments, docstrings, string literals, log messages, test
  files, the safe twin; a security *control* that mentions the threat (FP-05 shape).
- Score **per rule** (TP/FP/FN at rule + line level), not per file.
- **Pass bar:** every rule has the full matrix; each FP/FN is either fixed or listed as a known
  limitation in `docs/RULES.md`.

**Results (2026-11-15, `tests/test_rule_matrix.py`):** 216 cases over all 33 rules (29 regex +
4 AST), each with ≥3 positives and ≥3 hard negatives. 197 pass; 19 are `xfail(strict=True)`
tagged with a gap ID (fixing a gap makes its xfail fail, forcing the marker off).

| Gap | Cases | What fails |
|---|---|---|
| E1 comments / detector strings | 4 FP | jailbreak phrase in a comment or a blocklist literal; commented-out f-string and `os.system(mcp_result)` |
| E2 name-keyed | 4 FN | `user_text`, `question`, `sub`, `sub_executor` instead of the expected names |
| E3 string building | 2 FN | `+` and `%` instead of f-string |
| E4 aliased imports | 2 FN | `os as _o`, `subprocess as sp` |
| **E6** `os.environ.get()` | 1 FN | Env Var rule needs `os.environ(` / `os.getenv(` |
| **E7** word order | 1 FN | PII rule needs the PII word *before* the agent call on the line |
| **E8** word in prose | 2 FP | "password" / "tool_result" inside plain prompt text |
| **E9** bare variable logged | 1 FN | `print(api_key)` dropped by the value-reference guard |
| **E10** method-style loggers | 2 FN | `logger.info(` / `logger.debug(` never match (pattern needs `(` right after `logger`) |

Not gaps: Secret Passed to LLM only fires when the file also calls a model (deliberate guard,
covered by a negative case).

### T3 — Metamorphic / evasion testing (recall)
Apply meaning-preserving rewrites to every vulnerable fixture; the finding should survive.
- Rename variables; `f""` → `.format()` → `%` → `+` → `"".join()`; route through an
  intermediate variable; wrap in a helper function; split across lines; aliased imports
  (`import subprocess as sp`, `from os import system`); `getattr(os, "system")`.
- Reverse direction on safe fixtures: add trigger words in comments / unrelated strings — must
  stay clean.
- Build as a small transform script over `bench/fixtures`, output a survival table
  (rule × transform).
- **Pass bar:** survival rate reported per rule; anything below 50% becomes a tracked gap, not a
  silent miss.

**Results (2026-11-14, `python bench/mutate.py`):**

| Transform | Kept | Relabeled | Notes |
|---|---|---|---|
| identity | 23/23 | 0 | harness sanity |
| wrap_in_helper | 23/23 | 0 | |
| split_call_args | 14/16 | 1 | |
| rename_vars | 9/15 | 1 | |
| alias_imports | 1/3 | 0 | |
| f-string → `.format()` / `+` / `%` | 0/1 each | 1 / 0 / 0 | only one fixture uses an f-string |

Tracked gaps:
- **E1 — rules fire inside comments.** Prepending a two-line comment that mentions the threat
  flags 23/23 safe fixtures (Hardcoded Jailbreak, Prompt Injection via f-string, Tool Call
  Output Executed Directly). Commented-out code and security notes are common in real repos.
- **E2 — detection keys on variable names.** Renaming `user_input`/`prompt`/`query`/
  `result`/`response` loses 6 of 15 applicable findings (memory injection ×2, f-string
  injection, RAG DB query, unvalidated function-call result).
- **E3 — f-string rule misses `+` concatenation and `%` formatting** of the same input.
  (`.format()` is caught by its own rule.)
- **E4 — aliased imports evade sinks:** `import os as _o` (Env Var in Context) and
  `import subprocess as sp` (Tool Call Output Executed) are missed.
- **E5 — a call split across lines** loses Function Call Result Not Validated.
- Sample is thin for E3/E4 (1–3 applicable fixtures); T2 should add cases per rule.

### T4 — Independent ground truth (accuracy claim)
The only track that supports quoting a precision/recall number externally.
- Corpus built from sources the detector author did not write: public AI-app security
  advisories (e.g. the 2023 LangChain LLMMathChain / PALChain code-execution CVEs), published
  MCP tool-poisoning write-ups, OWASP LLM Top 10 examples, plus clean real code as negatives.
- Label **before** scanning; two labelers working independently; report Cohen's kappa;
  disagreements adjudicated and logged.
- **Pass bar:** ≥100 labeled positives and ≥100 negatives; precision and recall with 95% Wilson
  intervals; kappa ≥ 0.7, otherwise fix the labeling guide first.

### T5 — Real-world false-positive study
Grow `bench/agentsecbench` from 6 to ~30 repos at pinned commits across frameworks: LangChain,
LangGraph, LlamaIndex, CrewAI, AutoGen, OpenAI Agents SDK, official MCP servers, plus
`jaggernaut007/nexus-mcp` (already cloned for this work).
- Triage every HIGH/CRITICAL finding and a random sample of MEDIUM.
- ~96 triaged findings gives a ±10% interval on precision; aim for that.
- Record each FP root cause using the existing FP-xx case format.
- **Pass bar:** precision with CI per severity; top 3 FP root causes have an issue each.

**Results (2026-11-15).** 13 repos, shallow clones at these commits: langgraph 08a2016,
crewAI f4da03a, openai-agents-python 64fbde5, MCP servers e1dc4b1, MCP python-sdk 77001c9,
smolagents 57b9e40, pydantic-ai f93bcff, mem0 f1791da, gpt-researcher ddd4db3,
llama_index 99d7433, autogen 8390985, langchain ea17e48, nexus-mcp eeb6bc3.

1. First scan: 2,859 findings (2,811 HIGH/CRITICAL); 2,603 were Recursive Self-Invocation
   on ordinary `agent = Agent(...); agent.run(...)` usage. Rule tightened before triage.
2. Second scan: 255 HIGH/CRITICAL. Random sample of 96 (seed 2026) triaged by hand:
   **7 true positives → precision 7.3% (95% Wilson CI ≈ 3.6%–14.3%).**
   TPs: a real-looking OpenAI key in a committed Discord dump (llama_index); hardcoded
   remote MCP URLs in product code (pylon, posthog, logfire); unvalidated tool results put
   back into model context (crewAI, gpt-researcher); env-named file read into a prompt (CI
   script). Label rule: TP = code matches what the rule claims, outside test/fixture data.

   | FP root cause | ≈ count | Fix |
   |---|---|---|
   | test code (Test* agent classes, example URLs, jailbreak test data) | 32 | `Test*` classes excluded; rest is G7 |
   | `prompt = X.format(...)` with no user input in view | 29 | requires a user-input-like argument |
   | key-shaped text inside base64 cassettes / data dumps | 22 | token must start at a boundary |
   | `tool_def = tools.get(...)` dict lookup | 3 | HTTP-client receivers only |
   | placeholder `sk-xxxx…`; LLM "token" | 2 | placeholder filter; "token" left |

3. After those fixes, rescanning the **same** 96 files: all 7 TPs still flagged, FPs 89 → 21
   (in-sample precision 7/28 = 25%; optimistic because the fixes came from this sample).
   The remaining 21 are mostly test files (G7) and the Discord dump.
4. **Pending:** a fresh sample from a full post-fix rescan for an unbiased number (the
   rescan was stopped by the host for low memory). Cost of the fixes: crewAI scan 60 s → 70 s.

5. **G7 done:** LLM/AI behaviour findings in test/fixture paths report as LOW (credential
   rules excluded). Same sample at a HIGH threshold: 7 TPs still HIGH, FPs 21 → 10
   (in-sample precision 7/17 = 41%). The remaining 10 are a committed Discord dump (data),
   docs example notebooks, a docs tool, and an LLM "token" variable.
6. **Post-fix census (2026-11-16):** full rescan of the same 13 repos, one at a time, with
   all fixes including G7. HIGH/CRITICAL fell from 255 to **57**; every one was triaged
   (no sampling). **21 true positives → precision 36.8% (95% Wilson CI ≈ 25.5%–49.8%)**,
   up from 7.3%. TPs: 12 hardcoded remote MCP URLs in pydantic-ai plugins, 4 env-derived
   prompts in CI/example scripts, 2 unvalidated tool results (gpt-researcher, crewAI), the
   mem0 notebook memory-into-agent-prompt flow, and one real-looking OpenAI key committed in
   two llama_index Discord dumps. Of the 36 FPs, 18 are chat text in those Discord dump
   JSON files; 5 are docs notebooks formatting a user query into a RAG template, which the
   README's own definition would call vulnerable (counting them: 26/57 = 45.6%).
   Caveat: no sampling bias, but these are the same repos the fixes were tuned on, so this
   is not yet an unseen-code accuracy number (that needs new repos or T4).
   Next lever: large JSON data files (chat dumps) — consider scanning `.json` only for
   MCP/agent config shapes.

### T6 — Differential baseline (optional)
Run Semgrep and CodeQL (Python) on the T4 + T5 corpus. Report overlap: what only secchecker
finds, what it misses that they find. Supports or refutes README §3.

### T7 — Robustness and performance
- Malformed Python (AST fallback must not crash or drop regex results), non-UTF-8 files, empty
  files, 10 MB guard edge, binary files, symlink loops, very deep trees, `.ipynb` notebooks.
- Determinism: two runs → byte-identical JSON (ordering included).
- Random-input fuzzing: scanner never raises; exit code 2 only on real runtime errors.
- Time + peak memory on the largest T5 repo, compared with `bench/perf.py` baseline.
- **Pass bar:** zero crashes; deterministic output; no >20% perf regression.

### T8 — CLI and report contract
- Exit codes 0/1/2 with `--severity-threshold`; every output format parses (SARIF schema test
  already exists — extend to JSON/XML).
- Config resolution (G9): a `.secchecker.yml` in the current directory must not silently apply to a different
  scan target — decide intended behavior, then test it.
- Default scan type is `llm` (PR #44) and help text agrees.

### T9 — Regression gate in CI
- `bench/run.py` scores at rule + line level and compares against a committed baseline.
- CI fails if any rule's recall drops or FP count rises on T2/T3/T5 corpora.

## Metrics

| Metric | Level | Where it comes from |
|---|---|---|
| Output exactness | per finding | T1 |
| Precision / recall | per rule, per category, overall | T2, T4 |
| Evasion survival | rule × transform | T3 |
| Real-world precision (95% CI) | per severity | T5 |
| Labeler agreement (kappa) | corpus | T4 |
| Crash count, determinism, time, memory | run | T7 |

Only T4 and T5 numbers may be quoted in the README or externally.

## Order and rough size

| Step | Track | Size |
|---|---|---|
| 1 | T1 + fix G1/G2 | small (1–2 sessions) |
| 2 | T2 matrix, rule-level scoring in `bench/run.py` | medium |
| 3 | T3 transform script | medium |
| 4 | T7 + T8 | small |
| 5 | T5 corpus to ~30 repos + triage | large (triage is manual) |
| 6 | T4 labeled corpus with second labeler | large, needs a second person |
| 7 | T9 CI gate | small, once T2/T3 exist |
| — | T6 | optional |

## Open decisions
- G9: should the current directory's config ever apply to a scan target outside the current directory?
- Who is the second labeler for T4?
- Does T5 triage of MEDIUM findings matter, or only HIGH/CRITICAL?
