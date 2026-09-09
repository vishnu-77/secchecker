# FP-03 — "MCP tool poisoning" fired on a plain function's `Args:` docstring

**Verdict:** False positive.
**Status:** Fixed — `_scan_python_docstrings` now suppresses a `system:` marker match
when the enclosing function actually has a parameter named `system` (an AST check on
the function signature, `_system_marker_is_param_doc` in `secchecker/llm_scanner.py`).
Re-scanning this repo confirms `demo_helpers.py` no longer appears. Every other
poisoning marker (`<IMPORTANT>`, "ignore previous instructions", ...) is unaffected —
verified by `bench/run.py` still scoring 1.00/1.00 on the regression corpus, and by
`test_poisoned_docstring_still_catches_real_system_directive` in
`tests/test_llm_scanner.py`, which uses the same "system:" text on a function with no
`system` parameter and confirms it still fires.

**Repo:** `anthropics/anthropic-cookbook` @ `a97b9a2dc300635f0c26b5e05d0b54bbe0279ee5`
**File:** `tool_use/memory_demo/demo_helpers.py:31-45,122-137`
**Rule:** `MCP - Poisoned Tool Docstring` (HIGH)
**Matched text:** `"run_conversation_turn: '\n        system:'"`,
`"run_conversation_loop: '\n        system:'"`

## The flow

```python
def run_conversation_turn(
    client: Anthropic,
    model: str,
    messages: list[dict[str, Any]],
    memory_handler: MemoryToolHandler,
    system: str,
    ...
) -> tuple[...]:
    """
    Run a single conversation turn, handling tool uses.

    Args:
        client: Anthropic client instance
        ...
        system: ...
    """
```

Two things are wrong with this match:

1. **Not an MCP tool at all.** `run_conversation_turn`/`run_conversation_loop` are
   plain Python helper functions in a memory-demo script — no `@mcp.tool()` decorator,
   no MCP server registration, nothing MCP-protocol-shaped anywhere near them.
2. **The "poisoned instruction" is a documented parameter named `system`.** The rule is
   evidently looking for an embedded `system:`-style role override inside a docstring
   (the real attack: a tool description that tries to inject fake system instructions
   into the calling LLM's context). Here `system:` is just the `Args:` line documenting
   a parameter literally named `system` (the function takes a `system: str` prompt
   argument) — completely ordinary Google-style docstring convention, not an injection
   payload.

## Root cause

The rule pattern-matches the literal substring `system:` inside any docstring, with no
check for (a) whether the enclosing function is actually exposed as a tool/MCP handler,
or (b) whether the match sits inside a normal `Args:`/`Returns:` doc block rather than
free-form prose attempting a role override.

## Why it matters for AgentSecBench

This is a precision problem specific to a category secchecker leads with in its own
README ("MCP tool poisoning" is the headline MCP check) — a Python codebase using
`system` as a parameter name in a docstring (extremely common, since `system` is the
standard Claude/OpenAI message-role vocabulary) will false-positive on this rule
without ever touching MCP.
