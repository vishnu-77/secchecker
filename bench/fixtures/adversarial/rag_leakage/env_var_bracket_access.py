# Adversarial: same env-var-into-context leak as
# vulnerable/rag_leakage/env_var_in_context.py, reading the variable via
# subscript access instead of a getenv()/environ.get() call.
import os


def build_context(base_context):
    context = base_context + " Deployment: " + os.environ["DEPLOYMENT_CONFIG"]
    return context
