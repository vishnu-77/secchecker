# Adversarial: same underlying bug as vulnerable/memory_injection/*.py (raw
# user input persisted without sanitization), using an object name common in
# real chatbot code that the memory-object vocabulary doesn't enumerate.


def remember(user_input, chat_history):
    chat_history.append(user_input)
