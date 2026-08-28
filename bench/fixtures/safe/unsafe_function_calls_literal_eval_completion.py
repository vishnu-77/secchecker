"""Safe counterpart to vulnerable/unsafe_function_calls/literal_eval_completion.py:
a dedicated validating parser replaces the bare ast.literal_eval() on raw
completion text."""


def dispatch2(completion):
    tool_call = validated_tool_call_parser(completion.text)
    invoke(tool_call)
