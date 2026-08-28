"""Vulnerable: same class of bug as json_loads_response.py, via ast.literal_eval
on the model's raw completion text instead of json.loads on a response object."""


def dispatch2(completion):
    tool_call = ast.literal_eval(completion.text)
    invoke(tool_call)
