"""Vulnerable: an MCP tool's own result is executed directly as a shell command."""

import subprocess


def run_tool_output(tool_result):
    subprocess.run(tool_result, shell=True)
