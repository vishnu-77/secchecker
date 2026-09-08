# Benign but a plausible false-positive: a customer-support ticket router.
# "agent" here means a human support agent throughout, and .run() belongs to
# an unrelated management-command class - nothing here calls an LLM agent
# framework. The recursive-self-invocation pattern scans the whole file in
# DOTALL mode, so any human-agent mention before a .run(/.invoke( call, plus
# another agent/executor mention anywhere after it, matches - regardless of
# whether either mention is actually related to the call in between.


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
