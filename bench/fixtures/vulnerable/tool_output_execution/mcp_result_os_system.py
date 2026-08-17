"""Vulnerable: an MCP tool's raw result handed to os.system() -- a distinct
sink+marker combo from tool_result_shell.py's subprocess.run(tool_result)."""

import os


def apply_tool_output(mcp_result):
    os.system(mcp_result)
