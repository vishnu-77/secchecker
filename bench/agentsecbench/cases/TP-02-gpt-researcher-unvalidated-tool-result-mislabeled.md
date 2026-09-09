# TP-02 — Real finding, wrong category label

**Verdict:** True positive on the underlying risk; the rule name is a mismatch for
what actually triggered it.

**Repo:** `assafelovic/gpt-researcher` @ `6f998577d547b1e54ec662dac63583aa11e3b84b`
**File:** `gpt_researcher/utils/tools.py:144-176`
**Rule:** `MCP - Unvalidated Tool Result in Prompt` (HIGH)

## The flow

```python
tool_result = "Tool execution failed"
for tool in tools:
    if tool.name == tool_name:
        ...
        tool_result = await tool.ainvoke(tool_args)
        ...
tool_message = ToolMessage(content=str(tool_result), tool_call_id=tool_id)
lc_messages.append(tool_message)
```

A tool's raw return value (which could be scraped web content, search results — whatever
that tool touches) is stringified and appended straight back into the LLM's conversation
history with no validation or sanitization in between. That's a legitimate instance of
"tool output re-enters privileged context unchecked" — the underlying risk the rule
name describes.

## The mismatch

The tools here are plain **LangChain tools** (`tool.ainvoke`/`tool.invoke`), not MCP
tools — nothing in this file touches the MCP protocol. secchecker's category label says
"MCP", but the pattern it actually matched on (`tool_result` flowing into a `message`)
is framework-agnostic — it would fire identically for any LangChain/LangGraph/generic
tool-calling loop. Correct catch, mislabeled surface: a user chasing this finding down
as "check my MCP config" would look in the wrong place.

## Why it matters for AgentSecBench

Recall is good here; the taxonomy isn't. Rename to something framework-neutral (e.g.
`Agentic - Unvalidated Tool Result in Prompt`) or split into an MCP-specific rule (keyed
to actual MCP client/server imports) plus a generic agentic-tool-loop rule — see
`docs/ROADMAP.md`'s "framework sink packs" item.
