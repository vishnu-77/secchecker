"""LLM/AI Security scanner — scans source code for LLM vulnerability patterns."""
import ast
import re
import json
import os
from pathlib import Path
from typing import Dict, List

from secchecker.llm_patterns import (
    LLM_PATTERNS, TOOL_POISONING_MARKERS,
    CAT_POISONED_DOCSTRING, CAT_POISONED_DESCRIPTION,
)
from secchecker.core import should_skip_directory, should_skip_file

_POISON_RE = re.compile(TOOL_POISONING_MARKERS)

# Compiled once at import instead of re-passing raw strings to re.findall()
# per file per pattern (flags, e.g. (?is), are already inline in each string).
_COMPILED_LLM_PATTERNS = {name: re.compile(p) for name, p in LLM_PATTERNS.items()}

# kwarg/dict-key names that hold an MCP/tool-schema description string
_DESCRIPTION_KEYS = {'description', 'tool_description'}

# ---------------------------------------------------------------------------
# Context guards for LLM_PATTERNS entries that match on keyword proximity
# alone (e.g. "message" near "secret") rather than an actual value flowing
# into an actual LLM/MCP call. That fires equally on documentation, log
# statements that print a var *name* not its value, and code that redacts a
# credential *from* the LLM sandbox as it does on a real secret-into-prompt
# flow (see bench/agentsecbench/cases/FP-01, FP-02, FP-04, FP-05, FP-06).
# Each guard below requires one extra piece of real evidence - not a new
# taint engine, one more condition on the same text the regex already scans.
# ---------------------------------------------------------------------------
_LLM_CALL_SINK_RE = re.compile(
    r'(?i)\.(?:create|complete|generate|invoke|stream)\s*\(|chat\.completions|'
    r'ChatCompletion|messages\.append\s*\(|\bAnthropic\s*\(|\bOpenAI\s*\('
)
_MCP_MARKER_RE = re.compile(
    r'(?i)\bmcp\b|modelcontextprotocol|ClientSession|FastMCP|@mcp\.tool|StdioServerParameters'
)
# A print/log call is only really exposing a secret's *value* if it reads one
# (os.environ/getenv) or interpolates a variable - not if it just contains
# the secret's *name* as plain string text (setup instructions, docs, etc).
# `{` alone (not a matched pair) is enough evidence of interpolation: the
# outer LLM_PATTERNS regex's trailing \b already truncates the match right
# at the keyword, before any closing brace.
_VALUE_REF_RE = re.compile(r'os\.(?:environ|getenv)\s*\(|\{')

# rule name -> guard(full_match_text, whole_file_content) -> bool (True = keep)
_CONTEXT_GUARDS = {
    "LLM - Secret Passed to LLM": lambda m, content: bool(_LLM_CALL_SINK_RE.search(content)),
    "LLM - API Key in Log Statement": lambda m, content: bool(_VALUE_REF_RE.search(m)),
    "MCP - Hardcoded MCP Server URL": lambda m, content: bool(_MCP_MARKER_RE.search(content)),
}

CAT_UNBOUNDED_LOOP = "Agentic - Agent Loop Without Exit Condition"
CAT_RECURSIVE_SUBAGENT = "Agentic - Recursive Self-Invocation Risk"

_LOOP_SINK_VERBS = {'run', 'invoke', 'call', 'complete'}
_UNBOUNDED_ITER_FUNCS = {'count', 'cycle'}  # itertools.count()/cycle(), however imported
_AGENT_LIKE_NAMES = {'agent', 'executor', 'agentexecutor', 'reactagent'}
_INVOKE_VERBS = {'run', 'invoke'}
# Nodes whose own break/return doesn't exit an *enclosing* loop.
_LOOP_SCOPE_BOUNDARY = (ast.For, ast.While, ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)

LLM_RELEVANT_EXTENSIONS = {
    '.py', '.js', '.ts', '.tsx', '.jsx',
    '.ipynb', '.yaml', '.yml', '.json',
    '.env', '.toml', '.cfg', '.ini',
}


def _read_file(filepath):
    # type: (str) -> str
    """Read file content with encoding fallback. Returns None on failure."""
    for encoding in ('utf-8', 'latin-1', 'cp1252'):
        try:
            with open(filepath, 'r', encoding=encoding) as f:
                return f.read()
        except (UnicodeDecodeError, IOError):
            continue
    return None


def _scan_content(content):
    # type: (str) -> Dict[str, List[str]]
    """Scan text content against LLM_PATTERNS."""
    findings = {}
    for pattern_name, pattern_regex in LLM_PATTERNS.items():
        try:
            guard = _CONTEXT_GUARDS.get(pattern_name)
            if guard is not None:
                # Need the full match text (group(0)) to evaluate the guard,
                # not just the captured groups findall() would give us -
                # still recorded in the same "group1 group2" shape as every
                # other rule so report output/format is unchanged.
                matches = [
                    mo.groups()[0] if len(mo.groups()) == 1 else ' '.join(mo.groups())
                    for mo in _COMPILED_LLM_PATTERNS[pattern_name].finditer(content)
                    if guard(mo.group(0), content)
                ]
            else:
                matches = _COMPILED_LLM_PATTERNS[pattern_name].findall(content)
            if matches:
                flat = []
                for m in matches:
                    flat.append(m if isinstance(m, str) else ' '.join(m))
                # Deduplicate
                seen = set()
                deduped = []
                for item in flat:
                    if item not in seen:
                        seen.add(item)
                        deduped.append(item)
                findings[pattern_name] = deduped
        except re.error:
            pass
    return findings


def _get_str_const(node):
    # type: (ast.expr) -> str
    """Return the string value of a Constant node, or empty string."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return ""


_SYSTEM_MARKER_RE = re.compile(r'(?i)^\s*system\s*:')


def _system_marker_is_param_doc(match_text, func_node):
    # type: (str, ast.AST) -> bool
    """True if a 'system:' poisoning-marker match is just a Google-style
    Args: line documenting a same-named function parameter (very common in
    Claude/OpenAI-shaped code, where `system` is an ordinary prompt
    argument), not an injected fake role header. See
    bench/agentsecbench/cases/FP-03. Only narrows this one marker - every
    other TOOL_POISONING_MARKERS alternative (<IMPORTANT>, "ignore previous
    instructions", ...) is unambiguous and still matches as before."""
    if not _SYSTEM_MARKER_RE.match(match_text):
        return False
    if not isinstance(func_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False
    names = {a.arg.lower() for a in list(func_node.args.args) + list(func_node.args.kwonlyargs)}
    return 'system' in names


def _scan_python_docstrings(tree):
    # type: (ast.AST) -> Dict[str, List[str]]
    """Detect MCP tool-poisoning: hidden instructions embedded in a tool
    function's docstring, or in a description= kwarg / dict-literal value.

    AST-based rather than regex-only so matches are scoped to genuine
    docstring/description contexts, not any occurrence of the marker text
    in the file (comments, unrelated strings, this scanner's own patterns).
    """
    findings = {}  # type: Dict[str, List[str]]

    def _add(category, detail):
        findings.setdefault(category, [])
        if detail not in findings[category]:
            findings[category].append(detail)

    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)):
            doc = ast.get_docstring(node, clean=False)
            if doc:
                m = _POISON_RE.search(doc)
                if m and not _system_marker_is_param_doc(m.group(0), node):
                    name = getattr(node, 'name', '<module>')
                    _add(CAT_POISONED_DOCSTRING, "{}: {!r}".format(name, m.group(0)[:60]))

        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in _DESCRIPTION_KEYS:
                    val = _get_str_const(kw.value)
                    if val and _POISON_RE.search(val):
                        snippet = _POISON_RE.search(val).group(0)[:60]
                        _add(CAT_POISONED_DESCRIPTION, "{}={!r}".format(kw.arg, snippet))

        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                key_str = _get_str_const(key) if key is not None else ""
                if key_str.lower() in _DESCRIPTION_KEYS:
                    val = _get_str_const(value)
                    if val and _POISON_RE.search(val):
                        snippet = _POISON_RE.search(val).group(0)[:60]
                        _add(CAT_POISONED_DESCRIPTION, "{}={!r}".format(key_str, snippet))

    return findings


def _walk_stopping_at(node, stop_types):
    # type: (ast.AST, tuple) -> Any
    """Yield every descendant of `node`, without descending into the children
    of a node whose type is in `stop_types` (the boundary node itself is still
    yielded once). Used to scope a check to "this loop" without also matching
    inside a nested loop/function that has its own, unrelated control flow."""
    stack = list(ast.iter_child_nodes(node))
    while stack:
        child = stack.pop()
        yield child
        if not isinstance(child, stop_types):
            stack.extend(ast.iter_child_nodes(child))


def _call_name(call):
    # type: (ast.Call) -> str
    """The bare function/method name of a Call node's callee, e.g. 'run' for
    both `run(...)` and `obj.run(...)`."""
    func = call.func
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _is_agent_like(name):
    # type: (str) -> bool
    return isinstance(name, str) and name.lower() in _AGENT_LIKE_NAMES


def _loop_has_sink_call(loop_node):
    # type: (ast.AST) -> bool
    """Any call to a .run()/.invoke()/.call()/.complete()-shaped sink,
    anywhere in the loop (including nested scopes - the risk is the same
    regardless of nesting depth)."""
    for node in _walk_stopping_at(loop_node, ()):
        if isinstance(node, ast.Call) and _call_name(node) in _LOOP_SINK_VERBS:
            return True
    return False


def _loop_has_exit(loop_node):
    # type: (ast.AST) -> bool
    """A break/return reachable without passing through a nested loop or
    function def - those have their own control flow and don't exit this
    loop."""
    for node in _walk_stopping_at(loop_node, _LOOP_SCOPE_BOUNDARY):
        if isinstance(node, (ast.Break, ast.Return)):
            return True
    return False


def _is_unbounded_iter_call(expr):
    # type: (ast.expr) -> bool
    """True for itertools.count(...)/cycle(...), however imported (module-
    qualified or bare via `from itertools import count`)."""
    return isinstance(expr, ast.Call) and _call_name(expr) in _UNBOUNDED_ITER_FUNCS


def _scan_unbounded_agent_loops(tree):
    # type: (ast.AST) -> Dict[str, List[str]]
    """Detect an agent-call sink inside a loop that can never terminate:
    `while True` or an unbounded iterator (itertools.count/cycle), with no
    break/return anywhere in its body.

    Replaces a DOTALL regex (`while\\s+True.*?\\.(run|invoke|call|complete)`)
    that matched across the whole file regardless of distance, had no
    break-awareness at all (would have flagged a properly-exited `while True`
    loop too), and was measured to blow up polynomially on adversarial input.
    """
    findings = {}  # type: Dict[str, List[str]]

    def _add(detail):
        findings.setdefault(CAT_UNBOUNDED_LOOP, [])
        if detail not in findings[CAT_UNBOUNDED_LOOP]:
            findings[CAT_UNBOUNDED_LOOP].append(detail)

    for node in ast.walk(tree):
        if isinstance(node, ast.While):
            test = node.test
            unbounded = isinstance(test, ast.Constant) and bool(test.value) is True
        elif isinstance(node, ast.For):
            unbounded = _is_unbounded_iter_call(node.iter)
        else:
            continue

        if unbounded and _loop_has_sink_call(node) and not _loop_has_exit(node):
            _add("line {}".format(node.lineno))

    return findings


def _scan_recursive_subagent_spawn(tree):
    # type: (ast.AST) -> Dict[str, List[str]]
    """Detect a function that both holds an agent/executor (as a parameter or
    a freshly-instantiated AgentExecutor/ReActAgent) and invokes an
    agent/executor-named object's .run()/.invoke() - spawning or driving
    another agent with no visible recursion-depth guard.

    Replaces a DOTALL regex requiring only an agent/executor-shaped word
    *somewhere* before a .run(/.invoke( call and another *somewhere* after it,
    anywhere in the whole file - which is what let it cross-match two
    unrelated functions separated by hundreds of lines (see
    bench/fixtures/benign_realistic/support_ticket_routing.py). Scoping to one
    function at a time is the actual fix; it isn't full recursion analysis
    (that belongs to the taint-engine work), just the same heuristic properly
    bounded.
    """
    findings = {}  # type: Dict[str, List[str]]

    def _add(detail):
        findings.setdefault(CAT_RECURSIVE_SUBAGENT, [])
        if detail not in findings[CAT_RECURSIVE_SUBAGENT]:
            findings[CAT_RECURSIVE_SUBAGENT].append(detail)

    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        has_agent_instantiation = False
        has_invoke_on_agent_like = False

        for node in ast.walk(func):
            if node is func or not isinstance(node, ast.Call):
                continue
            callee = node.func
            if isinstance(callee, ast.Name) and _is_agent_like(callee.id):
                has_agent_instantiation = True
            if isinstance(callee, ast.Attribute) and callee.attr in _INVOKE_VERBS:
                receiver = callee.value
                receiver_name = receiver.id if isinstance(receiver, ast.Name) else None
                if _is_agent_like(receiver_name):
                    has_invoke_on_agent_like = True

        # Merely receiving an agent as a parameter and calling .run() on it
        # once is normal, safe agent usage - the risk is specifically
        # *spawning a new* agent-like instance from within the function.
        if has_agent_instantiation and has_invoke_on_agent_like:
            _add("{}: line {}".format(func.name, func.lineno))

    return findings


def _merge_findings(target, source):
    # type: (Dict[str, List[str]], Dict[str, List[str]]) -> None
    """Merge `source` findings into `target` in place, deduplicating matches
    within each category."""
    for category, matches in source.items():
        target.setdefault(category, [])
        for m in matches:
            if m not in target[category]:
                target[category].append(m)


def _scan_python_ast_checks(content):
    # type: (str) -> Dict[str, List[str]]
    """Every AST-based check that applies to Python source: tool-poisoning
    docstrings/descriptions, unbounded agent loops, recursive sub-agent
    spawning. Shared between scan_file_llm's .py path and notebook cells."""
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError):
        return {}
    findings = {}  # type: Dict[str, List[str]]
    _merge_findings(findings, _scan_python_docstrings(tree))
    _merge_findings(findings, _scan_unbounded_agent_loops(tree))
    _merge_findings(findings, _scan_recursive_subagent_spawn(tree))
    return findings


def _scan_notebook(filepath):
    # type: (str) -> Dict[str, List[str]]
    """Extract source from Jupyter notebook cells and scan."""
    content = _read_file(filepath)
    if content is None:
        return {}
    try:
        nb = json.loads(content)
        cells = nb.get('cells', [])
        all_source = []
        for cell in cells:
            source = cell.get('source', [])
            if isinstance(source, list):
                all_source.append(''.join(source))
            elif isinstance(source, str):
                all_source.append(source)
        joined = '\n'.join(all_source)
        findings = _scan_content(joined)
        _merge_findings(findings, _scan_python_ast_checks(joined))
        return findings
    except (ValueError, KeyError, TypeError):
        raw = _read_file(filepath)
        return _scan_content(raw) if raw else {}


def scan_file_llm(filepath):
    # type: (str) -> Dict[str, List[str]]
    """Scan a single file for LLM/AI security issues."""
    path = Path(filepath)
    if not path.exists() or not path.is_file():
        return {}

    if path.suffix.lower() not in LLM_RELEVANT_EXTENSIONS and path.name != '.env':
        return {}

    if should_skip_file(path):
        return {}

    if path.suffix.lower() == '.ipynb':
        return _scan_notebook(filepath)

    content = _read_file(filepath)
    if content is None:
        return {}
    findings = _scan_content(content)
    if path.suffix.lower() == '.py':
        _merge_findings(findings, _scan_python_ast_checks(content))
    return findings


def scan_directory_llm(directory):
    # type: (str) -> Dict[str, Dict[str, List[str]]]
    """Scan a directory recursively for LLM/AI security patterns."""
    if not os.path.exists(directory):
        raise FileNotFoundError("Directory not found: {}".format(directory))

    results = {}
    directory_path = Path(directory)

    for root, dirs, files in os.walk(directory_path):
        root_path = Path(root)
        dirs[:] = [d for d in dirs if not should_skip_directory(Path(d))]

        for filename in files:
            file_path = root_path / filename
            if file_path.suffix.lower() not in LLM_RELEVANT_EXTENSIONS and file_path.name != '.env':
                continue
            findings = scan_file_llm(str(file_path))
            if findings:
                try:
                    rel = file_path.relative_to(directory_path)
                    results[str(rel)] = findings
                except ValueError:
                    results[str(file_path)] = findings

    return results
