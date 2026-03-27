"""AST-based Python security scanner for secchecker.

Complements the regex scanner with structural analysis:
- Hardcoded string literals in security-sensitive assignments
- eval() / exec() calls (with any argument)
- Simplified taint tracking: user-controlled sources -> dangerous sinks

Only runs on .py files. Falls back gracefully on parse errors.
Zero external dependencies (stdlib ast only).
"""
import ast
import os
from pathlib import Path
from typing import Dict, List

try:
    from secchecker.core import should_skip_file, should_skip_directory
except ImportError:
    def should_skip_file(p):
        return False

    def should_skip_directory(p):
        return False


# ---------------------------------------------------------------------------
# Patterns: assignment target names that indicate sensitive values
# ---------------------------------------------------------------------------

_SECRET_NAMES = {
    'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
    'token', 'auth_token', 'access_token', 'refresh_token',
    'private_key', 'privatekey', 'secret_key', 'secretkey',
    'db_password', 'database_password', 'db_pass', 'db_pwd',
    'aws_secret', 'aws_access_key', 'aws_secret_key',
    'stripe_key', 'stripe_secret', 'openai_api_key', 'anthropic_api_key',
    'encryption_key', 'signing_key', 'client_secret',
    'oauth_token', 'bearer_token', 'webhook_secret',
}

# Source variable names / attribute paths that carry user-controlled data
_TAINT_SOURCES = {
    # WSGI / ASGI request inputs
    'request.args', 'request.form', 'request.data', 'request.json',
    'request.get_json', 'request.body', 'request.POST', 'request.GET',
    # stdlib
    'input', 'sys.stdin.read', 'sys.argv',
    # os.environ
    'os.environ', 'os.getenv',
}

# Sink call names that are dangerous when fed tainted data
_DANGEROUS_SINKS = {
    'eval', 'exec',
    'subprocess.run', 'subprocess.call', 'subprocess.Popen',
    'os.system', 'os.popen',
    # SQL (common ORM / driver patterns)
    'cursor.execute', 'db.execute', 'conn.execute', 'session.execute',
    'engine.execute',
    # LLM / completion calls
    'openai.ChatCompletion.create', 'openai.Completion.create',
    'client.chat.completions.create', 'client.completions.create',
    'llm.complete', 'llm.run', 'chain.run',
}

# Minimum length for a string literal to be reported as a hardcoded secret
_MIN_SECRET_LEN = 8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _name_is_sensitive(name):
    # type: (str) -> bool
    """Return True if *name* looks like it should hold a secret."""
    lower = name.lower().replace('-', '_')
    return lower in _SECRET_NAMES or any(kw in lower for kw in _SECRET_NAMES)


def _node_to_call_path(node):
    # type: (ast.expr) -> str
    """Flatten a Call's func node into a dotted string, best-effort."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _node_to_call_path(node.value)
        return "{}.{}".format(parent, node.attr) if parent else node.attr
    return ""


def _get_string_value(node):
    # type: (ast.expr) -> str
    """Return string value from a Constant/Str node, or empty string."""
    if isinstance(node, ast.Constant) and isinstance(node.s, str):
        return node.s
    # Python 3.7 compatibility
    if hasattr(ast, 'Str') and isinstance(node, ast.Str):
        return node.s
    return ""


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------

class _SecurityVisitor(ast.NodeVisitor):
    """Walk the AST and collect security findings."""

    def __init__(self):
        self.findings = {}  # type: Dict[str, List[str]]
        self._tainted_names = set()  # type: set

    def _add(self, category, detail):
        # type: (str, str) -> None
        if category not in self.findings:
            self.findings[category] = []
        if detail not in self.findings[category]:
            self.findings[category].append(detail)

    # ------------------------------------------------------------------
    # 1. Hardcoded secrets in assignments
    # ------------------------------------------------------------------

    def visit_Assign(self, node):
        # type: (ast.Assign) -> None
        val = _get_string_value(node.value)
        if val and len(val) >= _MIN_SECRET_LEN:
            for target in node.targets:
                target_name = ""
                if isinstance(target, ast.Name):
                    target_name = target.id
                elif isinstance(target, ast.Attribute):
                    target_name = target.attr
                if target_name and _name_is_sensitive(target_name):
                    # Truncate for display
                    display = val[:60] + "..." if len(val) > 60 else val
                    self._add(
                        "AST - Hardcoded Secret Assignment",
                        "{}={!r}".format(target_name, display),
                    )
        # Taint tracking: mark names that receive user-controlled values
        rhs = self._call_path_from_expr(node.value)
        if rhs and any(rhs.startswith(src) for src in _TAINT_SOURCES):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_names.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        # type: (ast.AnnAssign) -> None
        if node.value is None:
            return
        val = _get_string_value(node.value)
        if val and len(val) >= _MIN_SECRET_LEN:
            target_name = ""
            if isinstance(node.target, ast.Name):
                target_name = node.target.id
            elif isinstance(node.target, ast.Attribute):
                target_name = node.target.attr
            if target_name and _name_is_sensitive(target_name):
                display = val[:60] + "..." if len(val) > 60 else val
                self._add(
                    "AST - Hardcoded Secret Assignment",
                    "{}={!r}".format(target_name, display),
                )
        self.generic_visit(node)

    # ------------------------------------------------------------------
    # 2. eval() / exec() calls — always flag regardless of argument
    # ------------------------------------------------------------------

    def visit_Call(self, node):
        # type: (ast.Call) -> None
        call_path = _node_to_call_path(node.func)

        if call_path in ('eval', 'exec'):
            arg_repr = self._arg_summary(node)
            self._add("AST - eval/exec Call", "{}({})".format(call_path, arg_repr))

        # Dangerous sink called with tainted argument
        if call_path in _DANGEROUS_SINKS or any(
            call_path.endswith(sink.split('.')[-1]) for sink in _DANGEROUS_SINKS
        ):
            for arg in node.args:
                tainted_arg = self._tainted_arg_name(arg)
                if tainted_arg and tainted_arg in self._tainted_names:
                    self._add(
                        "AST - Tainted Input to Dangerous Sink",
                        "{}({}) [tainted: {}]".format(call_path, tainted_arg, tainted_arg),
                    )
            for kw in node.keywords:
                if kw.value and self._tainted_arg_name(kw.value) in self._tainted_names:
                    tainted = self._tainted_arg_name(kw.value)
                    self._add(
                        "AST - Tainted Input to Dangerous Sink",
                        "{}({}={}) [tainted]".format(call_path, kw.arg or '**', tainted),
                    )

        self.generic_visit(node)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _call_path_from_expr(self, node):
        # type: (ast.expr) -> str
        """Return dotted call path if *node* is a Call, else empty string."""
        if isinstance(node, ast.Call):
            return _node_to_call_path(node.func)
        # Attribute access without call (e.g. request.args)
        if isinstance(node, ast.Attribute):
            return _node_to_call_path(node)
        return ""

    def _tainted_arg_name(self, node):
        # type: (ast.expr) -> str
        """Return the variable name if *node* is a simple Name, else ''."""
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def _arg_summary(self, call_node):
        # type: (ast.Call) -> str
        """Return a short human-readable summary of the first argument."""
        if not call_node.args:
            return ""
        first = call_node.args[0]
        val = _get_string_value(first)
        if val:
            return repr(val[:40])
        if isinstance(first, ast.Name):
            return first.id
        return "..."


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_file_ast(filepath):
    # type: (str) -> Dict[str, List[str]]
    """AST-scan a single Python file. Returns findings dict (may be empty)."""
    path_obj = Path(filepath)
    if path_obj.suffix.lower() != '.py':
        return {}
    if should_skip_file(path_obj):
        return {}
    try:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as fh:
            source = fh.read()
        tree = ast.parse(source, filename=filepath)
    except SyntaxError:
        return {}
    except (OSError, IOError, PermissionError):
        return {}
    except Exception:
        return {}

    visitor = _SecurityVisitor()
    visitor.visit(tree)
    return visitor.findings


def scan_directory_ast(directory):
    # type: (str) -> Dict[str, Dict[str, List[str]]]
    """AST-scan all .py files in *directory* recursively."""
    results = {}
    directory_path = Path(directory)

    if not directory_path.exists():
        raise FileNotFoundError("Directory not found: {}".format(directory))

    if not directory_path.is_dir():
        findings = scan_file_ast(str(directory_path))
        if findings:
            results[str(directory_path)] = findings
        return results

    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not should_skip_directory(Path(d))]
        for filename in files:
            if not filename.endswith('.py'):
                continue
            file_path = root_path / filename
            findings = scan_file_ast(str(file_path))
            if findings:
                try:
                    rel = file_path.relative_to(directory_path)
                    results[str(rel)] = findings
                except ValueError:
                    results[str(file_path)] = findings

    return results
