"""Safe counterpart to vulnerable/tool_output_execution/eval_llm_output.py:
the model's output is parsed as data and schema-validated, never eval()'d."""

import json


def handle_response(completion):
    result = json.loads(completion.text)
    return validate_schema(result)
