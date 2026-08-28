"""Safe counterpart to vulnerable/unsafe_function_calls/json_loads_response.py:
the proposed function call is parsed and validated against the tool schema
before dispatch, instead of a bare json.loads() straight from the response."""


def dispatch(response):
    function_call = parse_and_validate(response.content, schema=TOOL_SCHEMA)
    execute(function_call)
