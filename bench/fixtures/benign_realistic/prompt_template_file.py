# Benign but a plausible false-positive: loading a versioned, developer-
# authored template that ships with the app (not arbitrary or untrusted
# content) into the prompt variable. The pattern can't distinguish a
# trusted, repo-bundled file from an attacker-controlled one - documented
# static-analysis limitation, not a bug specific to this file.


def load_greeting_prompt():
    prompt = open("prompt_templates/greeting.txt").read()
    return prompt
