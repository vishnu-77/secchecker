"""Safe counterpart to vulnerable/rag_leakage/env_var_in_context.py:
deployment config never reaches the context; only a static, non-secret label does."""


def build_context(base_context):
    context = base_context + " Deployment: production"
    return context
