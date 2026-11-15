"""LLM/AI Security scanner — scans source code for LLM vulnerability patterns."""
import ast
import io
import re
import tokenize
import json
import os
from pathlib import Path
from typing import Any, Dict, List

from secchecker.llm_patterns import (
    LLM_PATTERNS, TOOL_POISONING_MARKERS,
    CAT_POISONED_DOCSTRING, CAT_POISONED_DESCRIPTION,
)
from secchecker.core import should_skip_directory, should_skip_file
from secchecker.validators import _looks_like_placeholder

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

_STR_LIT_RE = re.compile(r'([rRbBuUfF]{0,2})("""|\'\'\'|"|\')(.*?)\2', re.S)
_SECRET_WORD_RE = re.compile(r'(?i)\b(?:api_?key|secret|password|token|credential)\b')
_TOOL_RESULT_WORD_RE = re.compile(r'(?i)\b(?:tool_result|tool_output|mcp_result|function_result)\b')
_LOG_KEY_WORD_RE = re.compile(r'(?i)\b(?:api_key|openai_api_key|anthropic_api_key)\b')


def _line_of_match(mo, content):
    start = content.rfind('\n', 0, mo.start()) + 1
    end = content.find('\n', mo.end())
    return content[start:end if end != -1 else len(content)]


def _code_only(line):
    """*line* with string-literal text removed; f-string {...} parts are kept,
    since those are values, not prose."""
    def keep(m):
        if 'f' in m.group(1).lower():
            return ' '.join(re.findall(r'\{([^{}]*)\}', m.group(3)))
        return '""'
    return _STR_LIT_RE.sub(keep, line)


def _word_in_code(word_re):
    """Guard: the rule's keyword must appear as code on the line, not only as
    words inside a string (e.g. a prompt that *mentions* 'password')."""
    return lambda mo, content: bool(word_re.search(_code_only(_line_of_match(mo, content))))


# rule name -> guard(match_object, whole_file_content) -> bool (True = keep)
_CONTEXT_GUARDS = {
    "LLM - Secret Passed to LLM": lambda mo, content: (
        bool(_LLM_CALL_SINK_RE.search(content)) and _word_in_code(_SECRET_WORD_RE)(mo, content)),
    "LLM - API Key in Log Statement": lambda mo, content: (
        bool(_VALUE_REF_RE.search(mo.group(0))) or _word_in_code(_LOG_KEY_WORD_RE)(mo, content)),
    "MCP - Hardcoded MCP Server URL": lambda mo, content: bool(_MCP_MARKER_RE.search(content)),
    "MCP - Unvalidated Tool Result in Prompt": _word_in_code(_TOOL_RESULT_WORD_RE),
}
for _key_rule in ("OpenAI API Key", "Anthropic API Key", "HuggingFace Token", "Pinecone API Key",
                  "Weaviate API Key", "Groq API Key", "OpenRouter API Key", "xAI API Key",
                  "LangSmith API Key"):
    _CONTEXT_GUARDS["LLM - " + _key_rule] = lambda mo, content: not _looks_like_placeholder(mo.group(0))

# Sink patterns written against `os.` / `subprocess.`; a file that aliases or
# from-imports those modules gets per-file variants (see _patterns_for).
_ALIASABLE_MODULES = ('os', 'subprocess')

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


def _blank_py_comments(content):
    # type: (str) -> str
    """Replace Python comments with spaces (same length, so line/column
    positions and reported code are unchanged). Unparseable input is
    returned as-is."""
    lines = content.splitlines(True)
    try:
        for tok in tokenize.generate_tokens(io.StringIO(content).readline):
            if tok.type == tokenize.COMMENT:
                (row, col), (_, ecol) = tok.start, tok.end
                line = lines[row - 1]
                lines[row - 1] = line[:col] + ' ' * (ecol - col) + line[ecol:]
    except (tokenize.TokenError, IndentationError, SyntaxError, IndexError):
        return content
    return ''.join(lines)


def _patterns_for(content):
    # type: (str) -> Dict[str, Any]
    """Compiled LLM patterns, adjusted for `import os as X` and
    `from os import system` style imports in *content*."""
    subs = {}
    for mod in _ALIASABLE_MODULES:
        aliases = re.findall(r'^\s*import\s+{}\s+as\s+(\w+)'.format(mod), content, re.M)
        names = []
        for group in re.findall(r'^\s*from\s+{}\s+import\s+([\w\s,]+)$'.format(mod), content, re.M):
            names += [n.split()[0] for n in group.split(',') if n.strip()]
        if aliases or names:
            alt = '(?:{})\\.'.format('|'.join([mod] + aliases))
            if names:
                alt = '(?:{}|(?=(?:{})\\b))'.format(alt, '|'.join(names))
            subs[mod] = alt
    if not subs:
        return _COMPILED_LLM_PATTERNS
    out = {}
    for name, p in LLM_PATTERNS.items():
        for mod, alt in subs.items():
            p = re.sub(r'(?<![A-Za-z_]){}\\\.'.format(mod), lambda _m, a=alt: a, p)
        try:
            out[name] = re.compile(p)
        except re.error:
            out[name] = _COMPILED_LLM_PATTERNS[name]
    return out


def _scan_content(content, python=False):
    # type: (str, bool) -> Dict[str, List[str]]
    """Scan text content against LLM_PATTERNS. For Python source, comments
    are blanked first so a comment that *mentions* a threat doesn't fire."""
    if python:
        content = _blank_py_comments(content)
    compiled = _patterns_for(content)
    findings = {}
    for pattern_name, pattern_regex in LLM_PATTERNS.items():
        try:
            guard = _CONTEXT_GUARDS.get(pattern_name)
            # Report the full matched text (group(0)): capture groups are
            # fragments that don't appear in the file and can't be located.
            flat = [
                mo.group(0)
                for mo in compiled[pattern_name].finditer(content)
                if guard is None or guard(mo, content)
            ]
            if flat:
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


def _src_line(lines, lineno):
    # type: (List[str], int) -> str
    """The stripped source line at 1-based *lineno*: AST findings report real
    code (locatable by reporters), not a description like 'line 6'."""
    return lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""


def _marker_line(lines, str_node, text, m):
    # type: (List[str], ast.AST, str, Any) -> str
    """Source line holding regex match *m* inside string literal *str_node*."""
    return _src_line(lines, str_node.lineno + text.count("\n", 0, m.start()))


def _scan_python_docstrings(tree, lines):
    # type: (ast.AST, List[str]) -> Dict[str, List[str]]
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
                    _add(CAT_POISONED_DOCSTRING, _marker_line(lines, node.body[0].value, doc, m))

        elif isinstance(node, ast.Call):
            for kw in node.keywords:
                if kw.arg in _DESCRIPTION_KEYS:
                    val = _get_str_const(kw.value)
                    m = _POISON_RE.search(val) if val else None
                    if m:
                        _add(CAT_POISONED_DESCRIPTION, _marker_line(lines, kw.value, val, m))

        elif isinstance(node, ast.Dict):
            for key, value in zip(node.keys, node.values):
                key_str = _get_str_const(key) if key is not None else ""
                if key_str.lower() in _DESCRIPTION_KEYS:
                    val = _get_str_const(value)
                    m = _POISON_RE.search(val) if val else None
                    if m:
                        _add(CAT_POISONED_DESCRIPTION, _marker_line(lines, value, val, m))

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
    if not isinstance(name, str):
        return False
    n = name.lower()
    return n in _AGENT_LIKE_NAMES or n.endswith(('agent', 'executor'))


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


def _scan_unbounded_agent_loops(tree, lines):
    # type: (ast.AST, List[str]) -> Dict[str, List[str]]
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
            _add(_src_line(lines, node.lineno))

    return findings


def _scan_recursive_subagent_spawn(tree, lines):
    # type: (ast.AST, List[str]) -> Dict[str, List[str]]
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

    agent_methods = {
        n for c in ast.walk(tree) if isinstance(c, ast.ClassDef) and _is_agent_like(c.name) and not c.name.startswith('Test')
        for n in c.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        spawn_line = 0  # first agent instantiation: the risky line, reported
        has_invoke_on_agent_like = False

        for node in ast.walk(func):
            if node is func or not isinstance(node, ast.Call):
                continue
            callee = node.func
            if isinstance(callee, ast.Name) and _is_agent_like(callee.id):
                spawn_line = spawn_line or node.lineno
            if isinstance(callee, ast.Attribute) and callee.attr in _INVOKE_VERBS:
                receiver = callee.value
                receiver_name = receiver.id if isinstance(receiver, ast.Name) else None
                if _is_agent_like(receiver_name):
                    has_invoke_on_agent_like = True

        # Merely receiving an agent as a parameter and calling .run() on it
        # once is normal, safe agent usage - and so is creating an agent and
        # running it (`agent = Agent(...); agent.run(q)`, thousands of hits in
        # real repos). The risk is an agent's own code - a function handed an
        # agent, or a method of an agent class - spawning *another* one.
        args = func.args.args + func.args.kwonlyargs
        holds_agent = func in agent_methods or any(_is_agent_like(a.arg) for a in args)
        if spawn_line and has_invoke_on_agent_like and holds_agent:
            _add(_src_line(lines, spawn_line))

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
    lines = content.splitlines()
    findings = {}  # type: Dict[str, List[str]]
    _merge_findings(findings, _scan_python_docstrings(tree, lines))
    _merge_findings(findings, _scan_unbounded_agent_loops(tree, lines))
    _merge_findings(findings, _scan_recursive_subagent_spawn(tree, lines))
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
        findings = _scan_content(joined, python=True)
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
    is_py = path.suffix.lower() == '.py'
    findings = _scan_content(content, python=is_py)
    if is_py:
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
