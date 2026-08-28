"""Safe counterpart to vulnerable/unsafe_function_calls/pii_to_external_agent.py:
sensitive identifiers are redacted before any text reaches the external agent call."""


def escalate_to_agent(customer, external_llm):
    prompt_text = "Customer inquiry needs review. Please advise the agent on next steps."
    return external_llm.complete(prompt_text)
