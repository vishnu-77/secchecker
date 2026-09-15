"""AST-based Python security scanner for secchecker.

Complements pattern matching with structural analysis:
- Hardcoded string literals in security-sensitive assignments
- Context-aware AI credential usage in provider/client initialisation
- eval() / exec() calls (with any argument)
- Limited, lexical-scope taint tracking: user-controlled sources -> dangerous sinks

Only runs on .py files. Falls back gracefully on syntax/read errors.
Unexpected analyser failures are allowed to propagate so callers can distinguish
an analysis error from a genuinely clean file.
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
    if isinstance(node, ast.Subscript):
        return _node_to_call_path(node.value)
    return ""


def _get_string_value(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


def _display_secret(value):
    if len(value) <= 8:
        return "<redacted>"
    return "{}...{}".format(value[:4], value[-4:])


def _path_matches(candidate, expected):
    """Match a canonical call path without reducing it to a bare method name."""
    return candidate == expected or candidate.endswith('.' + expected)


class _SecurityVisitor(ast.NodeVisitor):
    """Walk the AST and collect findings with deliberately bounded context.

    This is not whole-program taint analysis. State is lexical-scope aware and
    propagates through direct assignments and simple expression composition.
    Calls through unknown helper functions are not assumed to preserve taint.
    """

    def __init__(self):
        self.findings = {}  # type: Dict[str, List[str]]
        # Each scope maps name -> bool. Keeping explicit False entries is
        # important: a local safe reassignment must shadow an outer tainted or
        # hardcoded binding rather than falling through to it.
        self._taint_scopes = [{}]
        self._hardcoded_scopes = [{}]

    def _add(self, category, detail):
        if category not in self.findings:
            self.findings[category] = []
        if detail not in self.findings[category]:
            self.findings[category].append(detail)

    def _push_scope(self):
        self._taint_scopes.append({})
        self._hardcoded_scopes.append({})

    def _pop_scope(self):
        self._taint_scopes.pop()
        self._hardcoded_scopes.pop()

    @staticmethod
    def _lookup(scopes, name):
        for scope in reversed(scopes):
            if name in scope:
                return bool(scope[name])
        return False

    def _set_taint(self, name, value):
        self._taint_scopes[-1][name] = bool(value)

    def _set_hardcoded(self, name, value):
        self._hardcoded_scopes[-1][name] = bool(value)

    def _is_name_tainted(self, name):
        return self._lookup(self._taint_scopes, name)

    def _is_name_hardcoded(self, name):
        return self._lookup(self._hardcoded_scopes, name)

    def _record_secret_assignment(self, target_name, node):
        val = _get_string_value(node)
        is_hardcoded = bool(
            val and len(val) >= _MIN_SECRET_LEN and _name_is_sensitive(target_name)
        )
        self._set_hardcoded(target_name, is_hardcoded)
        if not is_hardcoded:
            return
        self._add(
            CAT_HARDCODED_SECRET,
            "{}=<redacted:{} chars>".format(target_name, len(val)),
        )

    def _source_path(self, node):
        if isinstance(node, ast.Call):
            return _node_to_call_path(node.func)
        if isinstance(node, (ast.Attribute, ast.Subscript)):
            return _node_to_call_path(node)
        return ""

    def _is_direct_source(self, node):
        path = self._source_path(node)
        if not path:
            return False
        return any(_path_matches(path, source) for source in _TAINT_SOURCES)

    def _expr_is_tainted(self, node):
        if node is None:
            return False
        if isinstance(node, ast.Name):
            return self._is_name_tainted(node.id)
        if self._is_direct_source(node):
            return True
        if isinstance(node, ast.JoinedStr):
            return any(
                isinstance(value, ast.FormattedValue) and self._expr_is_tainted(value.value)
                for value in node.values
            )
        if isinstance(node, ast.BinOp):
            return self._expr_is_tainted(node.left) or self._expr_is_tainted(node.right)
        if isinstance(node, ast.BoolOp):
            return any(self._expr_is_tainted(value) for value in node.values)
        if isinstance(node, ast.IfExp):
            return self._expr_is_tainted(node.body) or self._expr_is_tainted(node.orelse)
        if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            return any(self._expr_is_tainted(elt) for elt in node.elts)
        if isinstance(node, ast.Dict):
            return any(self._expr_is_tainted(value) for value in node.values)
        return False

    def _assign_name(self, target, value):
        target_name = ""
        if isinstance(target, ast.Name):
            target_name = target.id
        elif isinstance(target, ast.Attribute):
            target_name = target.attr
        if not target_name:
            return
        self._record_secret_assignment(target_name, value)
        self._set_taint(target_name, self._expr_is_tainted(value))

    def visit_Assign(self, node):
        for target in node.targets:
            self._assign_name(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        if node.value is None:
            return
        self._assign_name(node.target, node.value)
        self.generic_visit(node)

    def _visit_function(self, node):
        # Decorators/defaults are evaluated in the enclosing scope.
        for decorator in node.decorator_list:
            self.visit(decorator)
        for default in list(node.args.defaults) + [d for d in node.args.kw_defaults if d is not None]:
            self.visit(default)

        self._push_scope()
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._pop_scope()

    def visit_FunctionDef(self, node):
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node):
        self._visit_function(node)

    def visit_ClassDef(self, node):
        for decorator in node.decorator_list:
            self.visit(decorator)
        for base in node.bases:
            self.visit(base)
        self._push_scope()
        try:
            for stmt in node.body:
                self.visit(stmt)
        finally:
            self._pop_scope()

    def _credential_expr_is_hardcoded(self, expr):
        """Explain hardcoded credential material without flagging env loading."""
        literal = _get_string_value(expr)
        if literal and len(literal) >= _MIN_SECRET_LEN:
            return "literal credential ({})".format(_display_secret(literal))
        if isinstance(expr, ast.Name) and self._is_name_hardcoded(expr.id):
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

    def _is_dangerous_sink(self, call_path):
        return any(_path_matches(call_path, sink) for sink in _DANGEROUS_SINKS)

    def _expr_label(self, node):
        if isinstance(node, ast.Name):
            return node.id
        path = self._source_path(node)
        if path:
            return path
        if isinstance(node, ast.JoinedStr):
            return "f-string"
        if isinstance(node, ast.BinOp):
            return "composed-expression"
        return "expression"

    def visit_Call(self, node):
        call_path = _node_to_call_path(node.func)

        self._check_ai_provider_credentials(node, call_path)

        if call_path in ('eval', 'exec'):
            arg_repr = self._arg_summary(node)
            self._add(CAT_EVAL_EXEC, "{}({})".format(call_path, arg_repr))

        if self._is_dangerous_sink(call_path):
            for arg in node.args:
                if self._expr_is_tainted(arg):
                    label = self._expr_label(arg)
                    self._add(
                        CAT_TAINTED_SINK,
                        "{}({}) [tainted: {}]".format(call_path, label, label),
                    )
            for kw in node.keywords:
                if kw.value is not None and self._expr_is_tainted(kw.value):
                    label = self._expr_label(kw.value)
                    self._add(
                        CAT_TAINTED_SINK,
                        "{}({}={}) [tainted]".format(call_path, kw.arg or '**', label),
                    )

        self.generic_visit(node)

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
