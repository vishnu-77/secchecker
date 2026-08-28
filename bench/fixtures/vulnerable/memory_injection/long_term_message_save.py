"""Vulnerable: raw conversational message text written straight into long-term memory
(different object/method combo from agent_memory.append() and vector_store.insert())."""


def persist(message, long_term_memory):
    long_term_memory.save(message)
