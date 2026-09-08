# Adversarial: same class of bug as vulnerable/prompt_injection/format_injection.py
# (user input woven into a prompt via string formatting), using Python's %
# operator instead of a .format(...) call.


def build_instruction(user_input):
    instruction = "Follow this instruction: %s" % (user_input,)
    return instruction
