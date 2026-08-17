"""Vulnerable: a model-proposed function call is deserialized and dispatched
without validating it against the tool's actual schema first."""


def dispatch(response):
    function_call = json.loads(response.content)
    execute(function_call)
