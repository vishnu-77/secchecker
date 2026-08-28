"""Vulnerable: an environment variable value is folded into the LLM context,
potentially leaking deployment secrets to the model."""

import os


def build_context(base_context):
    context = base_context + " Deployment: " + os.getenv("DEPLOYMENT_CONFIG")
    return context
