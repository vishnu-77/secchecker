"""Safe counterpart to vulnerable/memory_injection/raw_user_input_to_memory.py:
input is sanitized and validated before it ever reaches agent memory."""


def remember(user_input, agent_memory):
    sanitized = sanitize_and_validate(user_input)
    agent_memory.append(sanitized)
