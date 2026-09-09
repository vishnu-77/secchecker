# FP-07 — A TypeScript class field's JSDoc flagged as a secret-into-context flow

**Verdict:** False positive.
**Status:** Fixed — via the same `_LLM_CALL_SINK_RE` guard as FP-05/FP-06: this file has
no `.create(`/`Anthropic(`/`OpenAI(`-shaped call anywhere, so `LLM - Secret Passed to
LLM` no longer fires. Re-scanning `social-media-agent` confirms it now scans clean.

**Repo:** `langchain-ai/social-media-agent` @ `61053aacf46f5d484eb13aad947ad52a81271f13`
**File:** `src/clients/twitter/client.ts:52-77`
**Rule:** `LLM - Secret Passed to LLM` (CRITICAL) — matched on `"Context token"`

## The flow

```ts
/**
 * Basic Auth requires these environment variables:
 * - TWITTER_USER_TOKEN
 * - TWITTER_USER_TOKEN_SECRET
 * ...
 */
export class TwitterClient {
  private twitterToken: string | undefined;
  private twitterTokenSecret: string | undefined;

  /**
   * @param {string} [args.twitterToken] - Twitter access token (required if useArcade is true)
   * @param {string} [args.twitterTokenSecret] - Twitter access token secret (required if useArcade is true)
   */
  constructor(args: TwitterClientArgs) { ... }
```

A private field declaration and its JSDoc `@param` documentation — no LLM prompt,
message, or context object anywhere nearby. `twitterTokenSecret` is just a field name
following the SDK's own naming convention (Twitter's OAuth term for the field is
literally "token secret").

## Root cause

secchecker's LLM/agentic rules are regex-based and apply to any text file, not just
Python — this file matched purely because "token"/"secret" appear near a class named
`...Client` with fields documented in JSDoc, the same keyword-co-occurrence issue as
the Python cases (FP-01, FP-02, FP-06), but here there isn't even AST-level Python
context to fall back on for a second opinion — see also
[`GAP-02`](GAP-02-non-python-agent-code-invisible.md) on non-Python coverage generally.

## Why it matters for AgentSecBench

Applying Python-shaped LLM-context heuristics (built around `f"..."`, `.format()`,
`messages=[...]`) to non-Python source with no language-aware sink detection means the
regex layer is guessing from surface keywords alone in every other language — this is
one concrete instance of that guess going wrong.
