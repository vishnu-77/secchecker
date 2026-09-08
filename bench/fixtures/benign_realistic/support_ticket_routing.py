# Regression fixture: a customer-support ticket router. "agent" here means a
# human support agent throughout, and .run() belongs to an unrelated
# management-command class - nothing here calls an LLM agent framework.
#
# This used to be a real false positive: the recursive-self-invocation check
# was a whole-file DOTALL regex, so any human-agent mention before a
# .run(/.invoke( call, plus another agent/executor mention anywhere after it
# - regardless of distance or relatedness - matched. Rewriting that check as
# an AST scan scoped to one function at a time (llm_scanner.py,
# _scan_recursive_subagent_spawn) fixed it outright rather than leaving it as
# a documented limitation. Kept here as a regression check against that bug
# recurring, not as a currently-active false positive.


def assign_to_agent(ticket):
    """Assign an open ticket to the next available support agent."""
    ticket.queue = "agent-pool"
    return ticket


class SyncTicketsCommand:
    def handle(self, *args, **options):
        self.run(*args, **options)

    def run(self, *args, **options):
        return sync_all_open_tickets()


def notify_agent(ticket):
    """Email the assigned agent that a new ticket needs attention."""
    send_email(ticket.assigned_agent.email, "New ticket assigned")
