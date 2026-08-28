"""Vulnerable: the model's own output is passed straight to eval()."""


def handle_response(completion):
    result = eval(completion.text)
    return result
