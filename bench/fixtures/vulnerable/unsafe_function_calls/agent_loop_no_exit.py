"""Vulnerable: an agent loop with no bounded exit condition -- while True driving
repeated model calls with no max-iteration or done-check."""


def run_agent_forever(agent):
    while True:
        agent.run()
