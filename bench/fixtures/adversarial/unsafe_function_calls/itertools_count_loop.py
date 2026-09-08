# Adversarial: same unbounded-agent-loop bug as
# vulnerable/unsafe_function_calls/agent_loop_no_exit.py, written as an
# itertools.count() for-loop instead of the pattern's fixed loop-header
# tokens - an equally unbounded, equally common idiom.
import itertools


def run_agent_forever(agent):
    for _ in itertools.count():
        agent.run()
