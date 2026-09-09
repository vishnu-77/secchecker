# FP-02 — Printing an env-var *name* (setup instructions) flagged as printing its value

**Verdict:** False positive (recurs 5x across the corpus — see "Also seen").
**Status:** Fixed for this file — `secchecker/llm_scanner.py`'s `_VALUE_REF_RE` guard
now requires `os.environ`/`getenv(` or an interpolated `{var}` in the matched call
before `LLM - API Key in Log Statement` fires; a bare literal name no longer counts.
Re-scanning this repo confirms `sre_bot_slack.py` no longer appears. **Not fixed:** the
5 `.triage/*.json` instances noted below — JSON content is brace-dense by construction,
so the same "does a `{` appear nearby" check that correctly reads an f-string as
interpolation can't tell that apart from ordinary JSON syntax. Still open; needs a
narrower interpolation check (e.g. `{` immediately followed by an identifier and a
closing `}` before the next non-identifier char) or scoping the guard to `.py`/`.ipynb`
content only.

**Repo:** `anthropics/anthropic-cookbook` @ `a97b9a2dc300635f0c26b5e05d0b54bbe0279ee5`
**File:** `claude_agent_sdk/site_reliability_agent/examples/sre_bot_slack.py:77-90`
**Rule:** `LLM - API Key in Log Statement` (MEDIUM)

## The flow

```python
missing_vars = []
for var in ["ANTHROPIC_API_KEY", "SLACK_BOT_TOKEN", "SLACK_APP_TOKEN"]:
    if not os.environ.get(var):
        missing_vars.append(var)

if missing_vars:
    print("❌ Missing required configuration:")
    for var in missing_vars:
        print(f"   - {var}")          # prints the *name*, e.g. "ANTHROPIC_API_KEY"
    print("   Create a .env file in this directory with:")
    print("       ANTHROPIC_API_KEY=your-anthropic-key")   # literal placeholder text
```

No secret value is ever read or printed. This is setup-error UX: tell the user which
env vars are unset and show them a placeholder `.env` template. The literal string
`ANTHROPIC_API_KEY` appears near a `print(...)` call, which is enough to trigger the
rule.

## Root cause

Same class as FP-01: the rule keys on the *name* of a well-known secret env var
appearing textually close to a logging call. It can't tell "the variable holding the
secret's value is being printed" apart from "the string that happens to be that
variable's name is printed as a label/instruction," because it never checks what's
actually being logged — a literal string vs. `os.environ[var]`/`os.getenv(var)`.

## Also seen (same shape, not filed as separate cases)

- `anthropic_docs.json` / `anthropic_summary_indexed_docs.json` (FP-01) — docs prose
  containing `export ANTHROPIC_API_KEY=...` example lines.
- `.triage/*.json` in `gpt-researcher` (5 occurrences of `LLM - API Key in Log
  Statement`) — a bug-triage dataset of GitHub issue text that *discusses* API-key
  logging as a bug report, not code that logs one.

## Why it matters for AgentSecBench

Fixing this specifically needs a value/identifier distinction the current regex layer
doesn't have: flag `print(f"...{os.environ['X']}...")` / `print(SECRET_VAR)`, don't
flag `print("X")` / `print(f"...{var_name}...")` where `var_name` holds a *name* string,
not the secret's value. That's a small, targeted improvement (not a rewrite) — worth
more than the RAG-corpus case above because it hits ordinary application code, not just
data/docs files.
