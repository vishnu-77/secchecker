"""Vulnerable: an agent executor spawning and invoking another executor from
within its own run, with no recursion-depth guard."""


def run_with_subagent(executor):
    result = executor.run()
    if result.needs_followup:
        sub_executor = AgentExecutor()
        return sub_executor.run()
