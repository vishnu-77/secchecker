# FP-06 — "the secret word" (a whimsical demo tool) flagged as a secret value

**Verdict:** False positive.
**Status:** Fixed — via the same `_LLM_CALL_SINK_RE` guard as FP-05: this example file
uses the Agents SDK's `Runner.run(...)` abstraction, not a raw `.create(`/`Anthropic(`/
`OpenAI(` call, so `LLM - Secret Passed to LLM` no longer fires anywhere in it. Re-scan
confirms the file no longer appears.

**Repo:** `openai/openai-agents-python` @ `83c737fd0b8d9a53bd39fa2a0856070417bb0bd3`
**File:** `examples/mcp/sse_example/main.py:51-54`
**Rule:** `LLM - Secret Passed to LLM` (CRITICAL) — matched on `"message secret"`

## The flow

```python
# Run the `get_secret_word` tool
message = "What's the secret word?"
print(f"\n\nRunning: {message}")
result = await Runner.run(starting_agent=agent, input=message)
```

This is a demo MCP server example whose sample tool is deliberately called
`get_secret_word` (a toy "guess the word" tool, not a credentials tool). The word
"secret" is part of the tool's playful name, not a leaked value.

## Root cause

Same as FP-01/FP-02: keyword co-occurrence (`secret` near a `message` variable feeding
an LLM call) with no distinction between "the English word secret" and "an actual
credential/token value."

## Why it matters for AgentSecBench

Confirms the pattern generalizes beyond docs/config files into ordinary demo/example
code that any repo ships. "Secret" is common enough as a word (secret word, secret
sauce, secret menu, `SecretStr`-the-pydantic-type-name, ...) that the rule needs either
a stricter value-shape check (looks like a key/token, e.g. entropy or a `sk-...`-style
prefix) or to require the matched word be a variable holding a real secret (e.g. sourced
from `os.environ`/a secrets manager), not free-text content.
