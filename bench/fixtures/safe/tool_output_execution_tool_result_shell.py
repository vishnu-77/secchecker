"""Safe counterpart to vulnerable/tool_output_execution/tool_result_shell.py:
the tool's result is quoted and logged, never handed to a shell."""

import logging
import shlex

logger = logging.getLogger(__name__)


def run_tool_output(tool_result):
    sanitized = shlex.quote(tool_result)
    logger.info("tool output: %s", sanitized)
