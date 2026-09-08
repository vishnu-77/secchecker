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

## Adversarial and benign_realistic corpora (added alongside this, still self-authored)
Two more corpora under `bench/fixtures/`, scored separately by `bench/run.py` (not folded into the
regression corpus's precision/recall — they aren't paired the same way and mixing them would
misrepresent both numbers):

- **`adversarial/<category>/`** (14 fixtures, recall-only, no safe twin): each is the *same*
  underlying vulnerability as an existing regression fixture, written with a different variable
  name, sink, or trigger phrase than the pattern's regex enumerates — indirect assignment, `%`
  formatting instead of `.format()`, `subprocess.call` instead of `.run`, a UK NI number instead of
  an SSN, and so on. **Result: 3/14 caught (21%).** This is the honest number the regression
  corpus's 1.00 recall can't show: the scanner generalizes well within a pattern's own vocabulary
  but not across even mild paraphrase or a different-but-equally-common stdlib call. Each miss is
  labeled with which specific vocabulary gap it demonstrates (see the fixture's own comment).
- **`benign_realistic/`** (4 fixtures, false-positive-only): not a random benign sample — a
  curated set of plausible real-world shapes chosen because they're likely to trip a specific
  pattern despite being safe (a human-support-agent module using the word "agent" near an unrelated
  `.run()` call; a trusted, repo-bundled prompt template loaded via `open()`; a non-secret env var
  folded into context). **Result: 3/4 still flagged.** These aren't scanner bugs so much as the
  documented limitation that regex matching can't verify actual trust/sensitivity of a source - see
  `THREAT_MODEL.md`.

Building these fixtures surfaced the same lesson as the SSN false positive below, twice: an early
draft of several `adversarial/` fixtures had their own explanatory comment accidentally quote the
literal trigger phrase they were testing the *absence* of (e.g. describing "the jailbreak pattern's
vocabulary does not include X" by literally writing out a real trigger phrase), which self-matched
and produced a false "still caught" result. Caught the same way as the SSN case — by running
`bench/run.py` and checking actual matched substrings, not by reasoning about the regex by hand.

## What's still missing before this is a credible accuracy claim
- **Scale further:** 14 adversarial + 4 benign_realistic fixtures is a real start, not yet enough
  for a confidence interval, and still concentrated on the patterns easiest to paraphrase by hand.
- **Independent construction or review:** all three corpora (regression, adversarial,
  benign_realistic) are still authored and scored entirely by the person who wrote the detector -
  exactly the kind of self-authored evidence that doesn't establish external validity on its own.
  An independent reviewer finding a case these corpora miss, filing it, and it becoming a new
  regression fixture is what would change that.

## Limitations
- Covers only the LLM/MCP/agentic scanner — secrets, DevSecOps (Docker/K8s/Terraform/CI), and
  dependency-scanner accuracy aren't measured here yet.
- Fixtures are single-file, single-function Python. Cross-file or cross-function taint (the
  scanner's AST engine is explicitly single-hop today, see `THREAT_MODEL.md`) isn't exercised.
- 24 fixtures is too small to report a confidence interval; treat every number here as a point
  estimate that will move as the corpus grows.
