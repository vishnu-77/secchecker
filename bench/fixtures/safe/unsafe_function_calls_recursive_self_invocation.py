"""Safe counterpart to vulnerable/unsafe_function_calls/recursive_self_invocation.py:
a single bounded executor run; no self-invoking sub-agent spawned."""


def run_with_subagent(executor):
    result = executor.run()
    return handle_followup(result)
