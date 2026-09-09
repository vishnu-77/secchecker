# GAP-01 — LangGraph's structured `state`/`Command` message passing is entirely outside detection

**Verdict:** Coverage gap (false negative by design, not a single bad match) — the
scanner produced **zero findings across the whole repository**.

**Repo:** `langchain-ai/langgraph-supervisor-py` @ `88859b34017ac3569bbd4a3092c7e77593a0a960`
**File:** `langgraph_supervisor/handoff.py` (entire file, 214 lines)
**Rules that should plausibly have an opinion here:** none exist. This is a gap in
what's checked, not a miss by an existing rule.

## The flow

```python
@tool(name, description=description)
def handoff_to_agent(
    state: Annotated[dict, InjectedState],
    tool_call_id: Annotated[str, InjectedToolCallId],
) -> Command:
    tool_message = ToolMessage(content=f"Successfully transferred to {agent_name}", ...)
    last_ai_message = cast(AIMessage, state["messages"][-1])
    ...
    return Command(
        graph=Command.PARENT,
        goto=[Send(agent_name, {**state, "messages": handoff_messages})],
    )
```

This is the core mechanism of a LangGraph multi-agent system: a worker agent's entire
accumulated `state["messages"]` — everything prior agents said, every tool result they
produced — is unpacked (`**state`) and forwarded to the *next* agent via a typed
`Command`/`Send` object, entirely through LangGraph's `InjectedState` /
`Command.PARENT` abstraction. There is no f-string, no `.format()`, no `prompt=`
literal anywhere — the entire trust-relevant transfer happens through framework
objects, dict spreads, and typed annotations.

## Why secchecker misses this

Every existing LLM/agentic rule (per `secchecker/llm_patterns.py`) is keyed to textual
prompt-construction idioms: f-strings, `.format()`, literal `content=`/`system=`
assignments, direct `os.environ`/`eval` calls. LangGraph's idiomatic data-flow — a
`TypedDict`/`dict` state object threaded through `Command`, `Send`,
`Annotated[dict, InjectedState]`, and `**state` spreads — never produces any of those
literal shapes. The risk this framework introduces (an agent's message history,
including whatever an upstream tool or agent injected into it, propagating unfiltered
into a downstream agent's context on every handoff) is structurally real but
structurally invisible to a scanner built around string-construction patterns.

## Why it matters for AgentSecBench

This is the concrete instance of `docs/ROADMAP.md`'s "framework sink packs" /
"cross-function agentic taint" item (today's taint tracking is single-file and
string-idiom-based). A LangGraph-aware pass would need to recognize `InjectedState`,
`Command`, `Send`, and `**state` spreads as taint-carrying operations in their own
right — not just look for stringy prompt construction. Until then, secchecker has
**no signal at all** on the most distinctive part of how LangGraph apps actually move
data between trust boundaries, which is a bigger gap than any single false positive
in this corpus.
