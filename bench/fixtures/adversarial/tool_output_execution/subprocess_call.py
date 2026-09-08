# Adversarial: same shape as vulnerable/tool_output_execution/tool_result_shell.py
# (a tool's raw result executed as a shell command), via subprocess.call()
# instead of subprocess.run() - an equally dangerous sink outside the
# pattern's vocabulary.
import subprocess


def run_tool_output(tool_result):
    subprocess.call(tool_result, shell=True)
