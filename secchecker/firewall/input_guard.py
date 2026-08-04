"""InputGuard — inspect user-supplied text before it enters an LLM prompt."""
from ._base_guard import _BaseGuard


class InputGuard(_BaseGuard):
    """Firewall guard for incoming user input.

    Usage::

        from secchecker.firewall import InputGuard, FirewallViolation

        guard = InputGuard(mode="active")
        try:
            result = guard.inspect(user_message)
            safe_text = result.modified_text   # redacted if needed
        except FirewallViolation as exc:
            # CRITICAL content blocked — do not pass to LLM
            raise
    """
