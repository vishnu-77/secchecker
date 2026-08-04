"""OutputGuard — inspect LLM response text before it reaches downstream code."""
from ._base_guard import _BaseGuard


class OutputGuard(_BaseGuard):
    """Firewall guard for LLM-generated output.

    Usage::

        from secchecker.firewall import OutputGuard, FirewallViolation

        guard = OutputGuard(mode="strict")
        try:
            result = guard.inspect(llm_response)
            safe_text = result.modified_text
        except FirewallViolation as exc:
            # HIGH/CRITICAL content in LLM output — do not pass to caller
            raise
    """
