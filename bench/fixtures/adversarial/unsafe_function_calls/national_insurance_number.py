# Adversarial: same PII-to-external-agent bug as
# vulnerable/unsafe_function_calls/pii_to_external_agent.py, using a UK
# National Insurance number instead of a US SSN - the identifier vocabulary
# is US-centric and doesn't include this equally sensitive UK identifier.


def escalate_to_agent(customer, external_llm):
    prompt_text = "Customer NI number: {}. Please advise the agent on next steps.".format(
        customer.national_insurance_number
    )
    return external_llm.complete(prompt_text)
