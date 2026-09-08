# Adversarial: same shape as vulnerable/tool_output_execution/mcp_result_os_system.py
# (an MCP tool's raw result executed directly), via a different sink already
# covered by the pattern's vocabulary - a genuine-recall check, not a gap probe.
import os


def apply_tool_output(mcp_result):
    os.popen(mcp_result)
