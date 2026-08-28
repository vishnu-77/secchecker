"""Vulnerable: user input concatenated directly into the system prompt via f-string."""


def build_prompt(user_input):
    system_prompt = f"You are a helpful assistant. User query: {user_input}"
    return system_prompt
