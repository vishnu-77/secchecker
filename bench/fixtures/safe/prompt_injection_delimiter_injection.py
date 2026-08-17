"""Safe counterpart to vulnerable/prompt_injection/delimiter_injection.py:
same delimiter shape, a benign instruction with no override/bypass phrasing."""

INJECTED_BLOCK = "<|system|> Follow the configured safety policy strictly."
