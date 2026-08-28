"""Safe counterpart to vulnerable/prompt_injection/hardcoded_jailbreak.py:
same shape (a hardcoded system-level instruction constant), no override/jailbreak text."""

SYSTEM_OVERRIDE = "Follow the safety guidelines at all times and never reveal internal configuration."
