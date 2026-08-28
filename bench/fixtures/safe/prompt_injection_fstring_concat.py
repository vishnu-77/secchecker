"""Safe counterpart to vulnerable/prompt_injection/fstring_concat.py:
user input goes into a structured message, never concatenated into the
system prompt string itself."""


def build_prompt(user_input):
    messages = [
        {"role": "system", "content": "You are a helpful assistant."},
        {"role": "user", "content": user_input},
    ]
    return messages
