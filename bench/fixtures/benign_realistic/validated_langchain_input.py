# Benign: a chain run on an explicitly validated variable, not the raw
# request - a true-negative sanity check that ordinary, already-sanitized
# usage doesn't misfire.


def handle(request):
    validated_query = sanitize(request.text)
    return agent_executor.run(validated_query)
