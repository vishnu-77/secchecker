"""Safe counterpart to vulnerable/memory_injection/long_term_message_save.py:
the message is summarized and validated before it's persisted."""


def persist(message, long_term_memory):
    summary = summarize_and_validate(message)
    long_term_memory.save(summary)
