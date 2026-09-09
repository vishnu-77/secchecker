# Evaluation

## Research question
How effectively can static analysis identify security conditions introduced by AI-native
applications — prompt injection, RAG leakage, MCP tool poisoning, tool-output execution, memory
injection, unsafe function-call handling — before deployment?

Full method: [`bench/methodology.md`](../bench/methodology.md). Reproduce with `python bench/run.py`.

## Method, in brief
- Paired fixtures: each vulnerable example has a safe twin with the one vulnerable line replaced
  by its safe equivalent, everything else identical.
- Scoring is binary per file (flagged / not flagged) against `scan_file_llm()`, secchecker's
  LLM/MCP/agentic scanner. No LLM judge — deterministic, offline, same input always gives the
  same output.

## Results — pattern-complete corpus (v0.4.2, 2026-08-18)

| Metric | Value |
|---|---|
| Fixtures | 46 (23 vulnerable / 23 safe) |
| True positives | 23 |
| False positives | 0 |
| True negatives | 23 |
| False negatives | 0 |
| Precision | 1.00 |
| Recall | 1.00 |
| F1 | 1.00 |
| Scan time | 0.05s |

Raw output: [`bench/results/0.5.0.json`](../bench/results/0.5.0.json). Every implemented
LLM/MCP/agentic pattern in these six categories has at least one vulnerable/safe pair (not an
arbitrary fixture count) — see `bench/methodology.md` for the exact rule.

## Results — adversarial and benign_realistic corpora (v0.5.0, 2026-09-08)

| Corpus | Fixtures | Result | What it measures |
|---|---|---|---|
| Adversarial (varied phrasing, recall-only) | 14 | **3 caught (21%)** | Same vulnerabilities as the regression corpus, deliberately paraphrased/reshaped — the honest recall number the 1.00 above can't show. |
| benign_realistic (known plausible-FP shapes) | 4 | **3 still flagged** | Curated realistic-but-safe shapes chosen because they plausibly trip a specific pattern. |

These are additive to the regression corpus above, not a replacement — see
`bench/methodology.md` for exactly what each fixture tests and why the numbers are scored
separately rather than blended into one precision/recall figure.

## Results — real-world corpus (AgentSecBench, v0.5.0, 2026-09-09)

Everything above is self-authored: fixtures written by the same person who wrote the detector.
[`bench/agentsecbench/`](../bench/agentsecbench/) runs the unmodified scanner against 6 real
open-source AI-agent repos instead (LangGraph, MCP reference servers, OpenAI Agents SDK,
gpt-researcher, and others) and hand-triages every finding. It's a small, first-pass sample —
12 hand-triaged findings, not a statistically powered benchmark — but it's the sharpest gap on
this page: precision on real code started far below the synthetic 1.00, traced to one dominant
root cause (keyword co-occurrence instead of actual data flow), with a shipped fix and a
before/after re-run on the identical corpus. Two structural coverage gaps (LangGraph's typed-state
idiom, non-Python MCP servers) are documented rather than hidden. Full numbers, root-cause
analysis, and fix write-up: [`bench/agentsecbench/SUMMARY.md`](../bench/agentsecbench/SUMMARY.md).

## Interpretation — read this before quoting the numbers above

**This is a regression corpus, not yet an accuracy benchmark.** Every fixture is authored with the
pattern it's meant to trigger already in mind, by the same person who wrote the detector. A
1.00/1.00 score here means "this release didn't regress on any case it was built to catch" — it
does **not** mean the scanner catches 100% of real-world prompt injection or MCP tool poisoning.
Novel phrasing, indirection through a helper function, or an obfuscated variant that the pattern
author didn't have in mind when writing the regex would need its own fixture to be measured at
all. (One concrete illustration: an earlier draft of this corpus had a false positive because a
*safe* fixture's own explanatory comment used the word "SSN" in prose — caught by actually running
the scanner, not by reasoning about the regex by hand.)

What would make this a real accuracy claim:
1. **Scale beyond one example per pattern** — the adversarial corpus above is a start (14 varied-
   phrasing fixtures, 21% recall), not yet enough for a confidence interval.
2. **Independent fixtures** — all three corpora (regression, adversarial, benign_realistic) are
   still written and scored by the person who wrote the detector.
3. **Adversarial cases** — done for a first, small set (above); a false negative is now a
   demonstrated reality (79% of the adversarial corpus), not a near-impossibility — but 14 fixtures
   covering hand-picked paraphrases isn't yet broad enough to generalize from.

Until then, treat this page as: "the method is real and reproducible, the current numbers are a
starting point, and the gap to a defensible accuracy claim is external validation and corpus
scale, not more code."

## Which problems this approach can and can't answer
See [`THREAT_MODEL.md`](../THREAT_MODEL.md) for the full boundary: what's statically detectable
pre-deployment versus what requires runtime governance (identity, delegated authority, multi-hop
consequence, context provenance) that a static scanner structurally cannot evaluate.
