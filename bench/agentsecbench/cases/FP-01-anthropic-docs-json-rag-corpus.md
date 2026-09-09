# FP-01 — RAG corpus *about* API keys flagged as secrets/PII *in* a prompt

**Verdict:** False positive (2 findings, same root cause).

**Repo:** `anthropics/anthropic-cookbook` @ `a97b9a2dc300635f0c26b5e05d0b54bbe0279ee5`
**File:** `capabilities/retrieval_augmented_generation/data/anthropic_docs.json`
(and its sibling `anthropic_summary_indexed_docs.json`, identical cause)
**Rules:** `LLM - Secret Passed to LLM` (CRITICAL), `LLM - API Key in Log Statement`
(MEDIUM), `Agentic - PII Passed to External Agent` (CRITICAL, matched on `"DOB Anthropic"`)
**Status:** Not fixed. The sink-presence guard added for FP-05/06/07 (require an
`Anthropic(`/`OpenAI(`/`.create(`-shaped call in the file) doesn't help here — this file
*is* Anthropic API documentation, so it genuinely contains real `client.messages.create`
example syntax as prose, satisfying the sink check without being a real flow. The
value-reference guard added for FP-02 doesn't help either, for the opposite reason:
JSON syntax is brace-dense, so the "`{` means interpolation" check the guard uses can't
distinguish a real f-string from ordinary JSON structure. This needs a different fix —
excluding non-code data files (JSON/notebooks-as-data, vs. `.py` source) from these two
rules, or requiring the matched value look like a real secret (entropy-checked, the way
`secchecker/validators.py` already does for the plain secrets scanner) rather than any
occurrence of the word. Left open — see `bench/agentsecbench/SUMMARY.md`.

## What's actually in the file

This is a static RAG evaluation corpus — scraped Anthropic API documentation, stored
as JSON for a retrieval demo. The matched text is *prose explaining how to use an API
key*:

> "All requests to the Claude API must include an `x-api-key` header with your API
> key... `export ANTHROPIC_API_KEY='your-api-key-here'`"

and, separately, a worked example about evaluating a "date of birth" extraction task
(`DOB` appears in prompt-engineering example text, not as an actual person's data).

## Root cause

The rule matches co-occurrence of trigger words (`api_key`, `password`, `secret`,
`token`, `DOB`) near context/prompt/message-shaped identifiers, within a keyword
window — it doesn't distinguish "a real secret *value* about to flow into a prompt"
from "the *word* appears in reference documentation being used as RAG source text."
A file whose entire purpose is *being* retrievable prompt context will always look
like "content entering a prompt" — that's not a bug in the file, it's the normal shape
of a RAG corpus.

## Why it matters for AgentSecBench

This is the single most common failure shape across the whole corpus (see also
FP-02, FP-05): the LLM scanner has no notion of "is this token a literal value or a
descriptive/documentation string" — it's lexical, not data-flow. A RAG/docs fixture is
exactly the kind of benign-but-keyword-dense file real AI apps ship in bulk, so this
FP shape will recur on every repo with a docs/eval corpus, not just this one.
