"""Safe counterpart to vulnerable/unsafe_function_calls/agent_loop_no_exit.py:
the loop is bounded by an explicit max-iteration exit condition."""


def run_agent_bounded(agent, max_iterations=10):
    for _ in range(max_iterations):
        result = agent.run()
        if result.is_done():
            break
