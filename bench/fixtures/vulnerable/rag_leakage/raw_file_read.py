"""Vulnerable: an entire file is read straight into the LLM context, unfiltered."""


def load_context():
    context = open("customer_records.txt").read()
    return context
