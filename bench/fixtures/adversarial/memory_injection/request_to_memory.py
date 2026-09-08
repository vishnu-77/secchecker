# Adversarial: same unsanitized-write-to-memory shape as the vulnerable/
# memory_injection/*.py fixtures, using a different in-vocabulary
# object+method+argument combination than any of the three base fixtures.


def remember_request(request, memory):
    memory.add(request)
