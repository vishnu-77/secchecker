"""AST-based Python security scanner for secchecker.

Complements pattern matching with structural analysis:
- Hardcoded string literals in security-sensitive assignments
- Context-aware AI credential usage in provider/client initialisation
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


_SECRET_NAMES = {
    'password', 'passwd', 'pwd', 'secret', 'api_key', 'apikey',
    'token', 'auth_token', 'access_token', 'refresh_token',
    'private_key', 'privatekey', 'secret_key', 'secretkey',
    'db_password', 'database_password', 'db_pass', 'db_pwd',
    'aws_secret', 'aws_access_key', 'aws_secret_key',
    'stripe_key', 'stripe_secret', 'openai_api_key', 'anthropic_api_key',
    'groq_api_key', 'openrouter_api_key', 'xai_api_key', 'huggingface_token',
    'pinecone_api_key', 'weaviate_api_key', 'langsmith_api_key',
    'encryption_key', 'signing_key', 'client_secret',
    'oauth_token', 'bearer_token', 'webhook_secret',
}

_AI_PROVIDER_CALLS = {
    'OpenAI', 'openai.OpenAI', 'AsyncOpenAI', 'openai.AsyncOpenAI',
    'Anthropic', 'anthropic.Anthropic', 'AsyncAnthropic', 'anthropic.AsyncAnthropic',
    'Groq', 'groq.Groq', 'AsyncGroq', 'groq.AsyncGroq',
    'OpenAIClient', 'AzureOpenAI', 'openai.AzureOpenAI',
    'Pinecone', 'pinecone.Pinecone',
    'weaviate.connect_to_custom', 'weaviate.connect_to_weaviate_cloud',
}

_AI_CREDENTIAL_KWARGS = {
    'api_key', 'apikey', 'token', 'access_token', 'auth_token',
    'client_secret', 'credential', 'credentials',
}

_TAINT_SOURCES = {
    'request.args', 'request.form', 'request.data', 'request.json',
    'request.get_json', 'request.body', 'request.POST', 'request.GET',
    'input', 'sys.stdin.read', 'sys.argv',
    'os.environ', 'os.getenv',
}

_DANGEROUS_SINKS = {
    'eval', 'exec',
    'subprocess.run', 'subprocess.call', 'subprocess.Popen',
    'os.system', 'os.popen',
    'cursor.execute', 'db.execute', 'conn.execute', 'session.execute',
    'engine.execute',
    'openai.ChatCompletion.create', 'openai.Completion.create',
    'client.chat.completions.create', 'client.completions.create',
    'llm.complete', 'llm.run', 'chain.run',
}

_MIN_SECRET_LEN = 8

CAT_HARDCODED_SECRET = "AST - Hardcoded Secret Assignment"
CAT_AI_CREDENTIAL_CONTEXT = "AST - Hardcoded AI Credential Used in Provider Client"
CAT_EVAL_EXEC = "AST - eval/exec Call"
CAT_TAINTED_SINK = "AST - Tainted Input to Dangerous Sink"

AST_SEVERITY_MAP = {
    CAT_HARDCODED_SECRET: "HIGH",
    CAT_AI_CREDENTIAL_CONTEXT: "CRITICAL",
    CAT_EVAL_EXEC: "HIGH",
    CAT_TAINTED_SINK: "CRITICAL",
}


def _name_is_sensitive(name):
    lower = name.lower().replace('-', '_')
    return lower in _SECRET_NAMES or any(kw in lower for kw in _SECRET_NAMES)


def _node_to_call_path(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _node_to_call_path(node.value)
        return "{}.{}".format(parent, node.attr) if parent else node.attr
    return ""


def _get_string_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _display_secret(value):
    if len(value) <= 8:
        return "<redacted>"
    return "{}...{}".format(value[:4], value[-4:])


class _SecurityVisitor(ast.NodeVisitor):
    """Walk the AST and collect security findings with limited context."""

    def __init__(self):
        self.findings = {}  # type: Dict[str, List[str]]
        self._tainted_names = set()
        self._hardcoded_secret_names = set()

    def _add(self, category, detail):
        if category not in self.findings:
            self.findings[category] = []
        if detail not in self.findings[category]:
            self.findings[category].append(detail)

    def _record_secret_assignment(self, target_name, node):
        val = _get_string_value(node)
        if not val or len(val) < _MIN_SECRET_LEN or not _name_is_sensitive(target_name):
            return
        self._hardcoded_secret_names.add(target_name)
        self._add(
            CAT_HARDCODED_SECRET,
            "{}=<redacted:{} chars>".format(target_name, len(val)),
        )

    def visit_Assign(self, node):
        for target in node.targets:
            target_name = ""
            if isinstance(target, ast.Name):
                target_name = target.id
            elif isinstance(target, ast.Attribute):
                target_name = target.attr
            if target_name:
                self._record_secret_assignment(target_name, node.value)

        rhs = self._call_path_from_expr(node.value)
        if rhs and any(rhs.startswith(src) for src in _TAINT_SOURCES):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted_names.add(target.id)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is None:
            return
        target_name = ""
        if isinstance(node.target, ast.Name):
            target_name = node.target.id
        elif isinstance(node.target, ast.Attribute):
            target_name = node.target.attr
        if target_name:
            self._record_secret_assignment(target_name, node.value)
        self.generic_visit(node)

    def _credential_expr_is_hardcoded(self, expr):
        """Explain hardcoded credential material without flagging env loading."""
        literal = _get_string_value(expr)
        if literal and len(literal) >= _MIN_SECRET_LEN:
            return "literal credential ({})".format(_display_secret(literal))
        if isinstance(expr, ast.Name) and expr.id in self._hardcoded_secret_names:
            return "hardcoded variable '{}'".format(expr.id)
        return ""

    def _check_ai_provider_credentials(self, node, call_path):
        if call_path not in _AI_PROVIDER_CALLS:
            return
        for kw in node.keywords:
            if not kw.arg or kw.arg.lower() not in _AI_CREDENTIAL_KWARGS:
                continue
            reason = self._credential_expr_is_hardcoded(kw.value)
            if reason:
                self._add(
                    CAT_AI_CREDENTIAL_CONTEXT,
                    "{}({}=...) uses {}".format(call_path, kw.arg, reason),
                )

    def visit_Call(self, node):
        call_path = _node_to_call_path(node.func)

        self._check_ai_provider_credentials(node, call_path)

        if call_path in ('eval', 'exec'):
            arg_repr = self._arg_summary(node)
            self._add(CAT_EVAL_EXEC, "{}({})".format(call_path, arg_repr))

        if call_path in _DANGEROUS_SINKS or any(
            call_path.endswith(sink.split('.')[-1]) for sink in _DANGEROUS_SINKS
        ):
            for arg in node.args:
                tainted_arg = self._tainted_arg_name(arg)
                if tainted_arg and tainted_arg in self._tainted_names:
                    self._add(
                        CAT_TAINTED_SINK,
                        "{}({}) [tainted: {}]".format(call_path, tainted_arg, tainted_arg),
                    )
            for kw in node.keywords:
                tainted = self._tainted_arg_name(kw.value) if kw.value else ""
                if tainted and tainted in self._tainted_names:
                    self._add(
                        CAT_TAINTED_SINK,
                        "{}({}={}) [tainted]".format(call_path, kw.arg or '**', tainted),
                    )

        self.generic_visit(node)

    def _call_path_from_expr(self, node):
        if isinstance(node, ast.Call):
            return _node_to_call_path(node.func)
        if isinstance(node, ast.Attribute):
            return _node_to_call_path(node)
        return ""

    def _tainted_arg_name(self, node):
        if isinstance(node, ast.Name):
            return node.id
        return ""

    def _arg_summary(self, call_node):
        if not call_node.args:
            return ""
        first = call_node.args[0]
        val = _get_string_value(first)
        if val:
            return repr(val[:40])
        if isinstance(first, ast.Name):
            return first.id
        return "..."


def scan_file_ast(filepath):
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
