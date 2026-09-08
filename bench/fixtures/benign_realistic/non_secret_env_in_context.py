# Benign but a plausible false-positive: a non-secret deployment label (AWS
# region) folded into an LLM prompt, not a credential. The pattern flags any
# environment-variable read assigned near a prompt-shaped variable name,
# regardless of whether that particular variable is actually sensitive -
# documented static-analysis limitation, not specific to this file.
import os


def build_context(base_note):
    context = base_note + " Region: " + os.getenv("AWS_REGION")
    return context
