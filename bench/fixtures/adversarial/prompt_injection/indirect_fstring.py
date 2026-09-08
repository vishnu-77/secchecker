# Adversarial: same f-string prompt-injection vulnerability as
# vulnerable/prompt_injection/fstring_concat.py, but the interpolated value
# is carried through an intermediate variable one hop before the f-string,
# instead of appearing directly inside the braces.


def build_prompt(user_input):
    msg = user_input
    system_prompt = f"You are a helpful assistant. User query: {msg}"
    return system_prompt
