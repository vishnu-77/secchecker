# Benchmark methodology

## Research question
How effectively does secchecker's static LLM/MCP/agentic scanner (`secchecker/llm_scanner.py`)
distinguish vulnerable AI-application code from safe code, across the risk categories it claims
to detect: prompt injection, RAG leakage, MCP tool poisoning, tool-output execution, memory
injection, and unsafe function-call handling?

## Method
- **Corpus:** paired fixtures under `bench/fixtures/vulnerable/<category>/` and
  `bench/fixtures/safe/`. Each safe fixture is the vulnerable file's exact structural twin with
  the one vulnerable line replaced by its safe equivalent (same function shape, same variable
  roles) — isolating the scanner's actual signal from confounds like file length or unrelated code.
- **Scoring:** binary, per file. A file with one or more findings from `scan_file_llm()` is
  classified positive. True positive = vulnerable fixture flagged. False negative = vulnerable
  fixture missed. False positive = safe fixture flagged. True negative = safe fixture left clean.
  Metrics (precision/recall/F1) are computed from those four counts by `bench/run.py`.
- **Deterministic:** no LLM judge, no sampling — same input always produces the same result.
- **Offline:** `bench/run.py` calls `scan_file_llm()` directly, in-process. No network calls.

## Running it
```
python bench/run.py [--version X.Y.Z]
```
Writes `bench/results/<version>.json` (per-file breakdown + aggregate metrics) and prints a summary.

## Current corpus: seed, not final
12 vulnerable / 12 safe (2 pairs per category, 6 categories) — a starting corpus, not the target
size. It currently scores 1.00 precision / 1.00 recall, and **that number should not be quoted
as evidence of general accuracy.** Every fixture here is a direct restatement of a pattern already
implemented in `secchecker/llm_patterns.py` — this corpus is a regression suite ("did this release
break detection of what it already claims to detect?"), not an adversarial benchmark.

## What's still missing before this is a credible accuracy claim
- **Scale:** grow toward 50 vulnerable / 50 safe per the project roadmap, covering variation
  within each category (different variable names, indirection through a helper function,
  multi-line construction) — not just one canonical shape per pattern.
- **Adversarial cases:** fixtures the pattern author didn't write with the regex already in mind —
  obfuscated or paraphrased variants that a real vulnerable codebase would actually contain, where
  a false negative is a real possibility rather than a near-impossibility.
- **Independent construction or review:** a corpus authored and scored entirely by the person who
  wrote the detector it's testing is exactly the kind of self-authored evidence that doesn't
  establish external validity on its own — see the project's plan for an independent reviewer to
  challenge this corpus (find a case the scanner misses, file it, fix it, add it as a regression).

## Limitations
- Covers only the LLM/MCP/agentic scanner — secrets, DevSecOps (Docker/K8s/Terraform/CI), and
  dependency-scanner accuracy aren't measured here yet.
- Fixtures are single-file, single-function Python. Cross-file or cross-function taint (the
  scanner's AST engine is explicitly single-hop today, see `THREAT_MODEL.md`) isn't exercised.
- 24 fixtures is too small to report a confidence interval; treat every number here as a point
  estimate that will move as the corpus grows.
