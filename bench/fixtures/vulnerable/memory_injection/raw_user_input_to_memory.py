"""Vulnerable: raw, unsanitized user input written straight into agent memory."""


def remember(user_input, agent_memory):
    agent_memory.append(user_input)
