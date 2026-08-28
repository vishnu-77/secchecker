"""Safe counterpart to vulnerable/prompt_injection/format_injection.py:
sanitized input goes into a plainly-named answer template, not a variable
named 'prompt'/'instruction' built live via .format()."""


def build_prompt(user_input):
    answer_template = "Answer the question: {}".format(sanitize(user_input))
    return {"role": "user", "content": answer_template}
