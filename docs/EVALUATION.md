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

## Results — seed corpus (v0.4.2, 2026-08-17)

| Metric | Value |
|---|---|
| Fixtures | 24 (12 vulnerable / 12 safe) |
| True positives | 12 |
| False positives | 0 |
| True negatives | 12 |
| False negatives | 0 |
| Precision | 1.00 |
| Recall | 1.00 |
| F1 | 1.00 |
| Scan time | 0.03s |

Raw output: [`bench/results/0.5.0-seed.json`](../bench/results/0.5.0-seed.json).

## Interpretation — read this before quoting the numbers above

**This is a regression corpus, not yet an accuracy benchmark.** Every fixture is a direct,
one-to-one restatement of a pattern already implemented in `secchecker/llm_patterns.py`, authored
by the same person who wrote the detector. A 1.00/1.00 score here means "this release didn't
regress on the exact cases it was built to catch" — it does **not** mean the scanner catches 100%
of real-world prompt injection or MCP tool poisoning. Novel phrasing, indirection through a helper
function, or an obfuscated variant that the pattern author didn't have in mind when writing the
regex would need its own fixture to be measured at all.

What would make this a real accuracy claim:
1. **Scale** — 50 vulnerable / 50 safe minimum, with variation within each category, not one
   canonical shape per pattern.
2. **Independent fixtures** — cases written or reviewed by someone other than the pattern author.
3. **Adversarial cases** — where a false negative is a live possibility, not a near-impossibility.

Until then, treat this page as: "the method is real and reproducible, the current numbers are a
starting point, and the gap to a defensible accuracy claim is external validation, not more code."

## Which problems this approach can and can't answer
See [`THREAT_MODEL.md`](../THREAT_MODEL.md) for the full boundary: what's statically detectable
pre-deployment versus what requires runtime governance (identity, delegated authority, multi-hop
consequence, context provenance) that a static scanner structurally cannot evaluate.
