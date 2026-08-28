"""Safe counterpart to vulnerable/tool_output_execution/mcp_result_os_system.py:
the tool's result is written to an audit log, never passed to a shell."""


def apply_tool_output(mcp_result, audit_log):
    audit_log.write(mcp_result)
