"""Vulnerable: a customer's SSN is forwarded directly into a call routed to an
external LLM/agent."""


def escalate_to_agent(customer, external_llm):
    prompt_text = "Customer SSN: {}. Please advise the agent on next steps.".format(customer.ssn)
    return external_llm.complete(prompt_text)
