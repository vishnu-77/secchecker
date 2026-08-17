"""Vulnerable: user input woven into the prompt via legacy .format() string building
(distinct detection mechanism from the f-string case in fstring_concat.py)."""


def build_instruction(user_input):
    instruction = "Follow this instruction: {}".format(user_input)
    return instruction
