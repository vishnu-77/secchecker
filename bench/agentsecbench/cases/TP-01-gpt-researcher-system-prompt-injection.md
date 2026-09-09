# TP-01 — Task-controlled data reaches an autonomous agent's system prompt

**Verdict:** True positive, and a plausible real vulnerability shape (not just a
pattern-shaped match).

**Repo:** `assafelovic/gpt-researcher` @ `6f998577d547b1e54ec662dac63583aa11e3b84b`
**File:** `deep_agents/agent.py:11-45,63-86`
**Rule:** `LLM - Prompt Injection via format()` (HIGH)

## The flow

```python
CHIEF_EDITOR_PROMPT = """You are the Chief Editor of an autonomous research team. \
...
{guidelines}"""

def build_agent(task: dict, run_dir: str):
    guidelines = ""
    if task.get("follow_guidelines") and task.get("guidelines"):
        rules = "\n".join(f"- {g}" for g in task["guidelines"])
        guidelines = f"\nThe report MUST follow these guidelines:\n{rules}"
    return create_deep_agent(
        model=model,
        tools=[quick_search],
        system_prompt=CHIEF_EDITOR_PROMPT.format(guidelines=guidelines),
        subagents=[researcher_subagent],
        backend=FilesystemBackend(root_dir=run_dir, virtual_mode=True),
    )
```

`task` is a per-request dict; `task["guidelines"]` is caller-supplied free text (a list
of strings a user submitting a research job would provide), joined and spliced straight
into the **system prompt** of an agent that has tool access and a filesystem backend.
secchecker found the `.format()` call directly, one function, no cross-file tracing
needed — this is the case its existing single-file taint tracking is built for, and it
worked.

## Why it matters for AgentSecBench

This is the scanner doing its job correctly on a real, unmodified file — not a curated
fixture. Whether it's *exploitable* depends on how far upstream `task["guidelines"]`
is from an untrusted caller (out of scope for a static-analysis-only check, and
secchecker doesn't claim to resolve that) — but flagging "external-shaped input
reaches a system prompt via string formatting" is exactly the right call to surface
for a human to check.
