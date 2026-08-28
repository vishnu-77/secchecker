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

## Current corpus: complete pattern coverage, not yet an accuracy claim
23 vulnerable / 23 safe (46 fixtures). Sized and organized by a specific rule, not an arbitrary
round number: **every LLM/MCP/agentic detection pattern relevant to the six risk categories below
has at least one vulnerable/safe pair**, covering each category's distinct sub-mechanisms (e.g.
prompt injection alone spans 5 separate patterns — f-string, `.format()`, hardcoded jailbreak,
role override, delimiter injection — each with its own pair, not 5 copies of the same shape).

It currently scores 1.00 precision / 1.00 recall, and **that number should not be quoted as
evidence of general accuracy.** Every fixture here is authored with the pattern it's meant to
trigger already in mind (by the same person who wrote the detector) — this corpus answers "does
this release still detect every case it was built to detect?" (a regression suite), not "how well
does it detect real, unseen vulnerable code?" (an accuracy benchmark). Those are different
questions; only the second one supports an external accuracy claim.

One data point on why running the corpus against the real scanner matters, not just reasoning
about the regexes by hand: the first version of this corpus had a false positive — a safe
fixture's own explanatory *comment* used the word "SSN" in prose, which the PII-detection pattern
correctly flagged as PII near an agent-call. Caught by `bench/run.py`, not by inspection.

## What's still missing before this is a credible accuracy claim
- **Scale beyond one example per pattern:** multiple independent phrasings/shapes per pattern —
  different variable names, indirection through a helper function, multi-line construction — not
  just the one canonical shape used here.
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
