"""LLM, MCP, and agentic AI security patterns — static detection for AI application vulnerabilities."""
from typing import Dict

LLM_PATTERNS: Dict[str, str] = {
    # Prompt Injection Risks
    "LLM - Prompt Injection via f-string": (
        r'(?i)(prompt|system_prompt|instruction|user_message)\s*[+]?=\s*f["\'].*\{(user_?input|query|request|message|content)\}'
    ),
    "LLM - Prompt Injection via format()": (
        r'(?i)(prompt|instruction)\s*=.*\.(format|%)\s*\('
    ),
    "LLM - Hardcoded Jailbreak Instruction": (
        r'(?i)(ignore\s+(previous|prior|all)\s+instructions|disregard\s+(your\s+)?(system\s+)?prompt|'
        r'forget\s+everything|you\s+are\s+now\s+DAN)'
    ),
    "LLM - Role Override Instruction": (
        r'(?i)(you\s+are\s+no\s+longer|act\s+as\s+if\s+you\s+have\s+no\s+restrictions|'
        r'pretend\s+you\s+are\s+an?\s+(evil|unrestricted|unfiltered))'
    ),
    "LLM - Prompt Delimiter Injection": (
        r'(?i)(#{3,}|<\|?(system|user|assistant|im_start)\|?>|<</?(SYS|INST)>>)\s*(ignore|override|bypass|disregard)'
    ),

    # RAG Leakage
    "LLM - RAG DB Query in Context": (
        r'(?i)(context|rag_context|retrieved_docs?)\s*=\s*(db|cursor|conn|session)\.(query|execute|fetchall|find)\s*\('
    ),
    "LLM - RAG Raw File in Prompt": (
        r'(?i)(context|prompt|message)\s*=\s*(open\s*\(|Path\s*\(.*\)\.read_text|file\.read\(\))'
    ),
    "LLM - Env Var in LLM Context": (
        r'(?i)(prompt|context|system_prompt)\s*.*os\.(environ|getenv)\s*\('
    ),

    # Dangerous Output Handling
    "LLM - Eval of LLM Output": (
        r'(?i)(eval|exec|subprocess\.run|os\.system)\s*\(\s*(llm_?response|completion|response\.text|output\.content)'
    ),
    "LLM - LangChain Unsafe Input": (
        r'(?i)(LLMChain|ConversationChain|AgentExecutor).*\.run\s*\(\s*(request|user_input|query)\s*\)'
    ),

    # Sensitive Data Exposure
    "LLM - Secret Passed to LLM": (
        r'(?i)(prompt|context|message|system_prompt)\s*[+=]+.*\b(api_?key|secret|password|token|credential)\b'
    ),
    "LLM - API Key in Log Statement": (
        r'(?i)(print|log|logger)\s*\(.*\b(api_key|openai_api_key|anthropic_api_key)\b'
    ),

    # Hardcoded AI Service Keys
    # OpenAI: legacy `sk-` (48 alnum) plus the current project/service-account/admin
    # key families (`sk-proj-`/`sk-svcacct-`/`sk-admin-`, ~150-char base64url body -
    # {40,} is a floor well under that, chosen only to skip short doc placeholders).
    "LLM - OpenAI API Key": r'sk-(proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|sk-[a-zA-Z0-9]{48}',
    # Anthropic: `sk-ant-` + a long base64url body. Not pinned to an exact length -
    # the previous {93} was brittle (a real api03 key is ~101 chars past `sk-ant-`,
    # already off) and would silently miss any future key generation (oat01, etc.)
    # that changes length. {80,} is a floor comfortably under every real variant.
    "LLM - Anthropic API Key": r'sk-ant-[a-zA-Z0-9\-_]{80,}',
    "LLM - HuggingFace Token": r'hf_[a-zA-Z0-9]{34,}',
    "LLM - Pinecone API Key": r'(?i)pinecone.*api[_\-]?key[\'"\s:=]+[a-zA-Z0-9\-]{32,}',
    "LLM - Weaviate API Key": r'(?i)weaviate.*api[_\-]?key[\'"\s:=]+[a-zA-Z0-9\-_]{32,}',
    "LLM - Groq API Key": r'gsk_[A-Za-z0-9]{20,}',
    "LLM - OpenRouter API Key": r'sk-or-v1-[A-Za-z0-9]{20,}',
    "LLM - xAI API Key": r'xai-[A-Za-z0-9]{20,}',
    "LLM - LangSmith API Key": r'lsv2_pt_[A-Za-z0-9_]{20,}',
    "LLM - System Prompt Hardcoded": r'(?i)system_prompt\s*=\s*[\'"](.{50,})[\'"]',

    # MCP (Model Context Protocol) Security
    "MCP - Unvalidated Tool Result in Prompt": (
        r'(?i)(prompt|context|system_prompt|message)\s*[+=]+.*\b(tool_result|tool_output|mcp_result|function_result)\b'
    ),
    "MCP - Tool Call Output Executed Directly": (
        r'(?i)(eval|exec|subprocess\.run|os\.system|os\.popen)\s*\(\s*(tool_result|tool_output|function_result|mcp_result|response\.content)'
    ),
    "MCP - Hardcoded MCP Server URL": (
        r'(?i)(mcp_server|mcp_url|server_url)\s*=\s*[\'"]https?://(?!localhost|127\.0\.0\.1)[^\'"]{6,}[\'"]'
    ),
    "MCP - Untrusted Tool Description in Prompt": (
        r'(?i)(tool_description|tool_schema|tool_def)\s*=\s*[^\n]*\.(get|fetch|request|load)\s*\('
    ),

    # Agentic AI Security
    "Agentic - Unsanitized Input to Agent Memory": (
        r'(?i)(memory|agent_memory|long_term_memory|vector_store)\.(add|store|save|insert|append)\s*\(\s*(user_?input|query|request|message)\s*\)'
    ),
    # "Agentic - Agent Loop Without Exit Condition" and "Agentic - Recursive
    # Self-Invocation Risk" moved to AST checks in llm_scanner.py
    # (_scan_unbounded_agent_loops / _scan_recursive_subagent_spawn). Both were
    # DOTALL regexes spanning the whole file with two lazy `.*?` spans each -
    # confirmed by direct measurement to blow up polynomially (~quadratic) on
    # adversarial input (a few hundred KB of repeated near-misses took minutes),
    # and cross-matched unrelated code separated by hundreds of lines (see the
    # git history of bench/fixtures/benign_realistic/support_ticket_routing.py,
    # a real false positive this AST rewrite retires). Removed from this dict
    # since they're no longer regex-matched; their category-name strings still
    # have entries in LLM_SEVERITY_MAP below and in owasp.py, now populated by
    # the AST findings instead.
    "Agentic - Function Call Result Not Validated": (
        r'(?i)(function_call|tool_call|action)\s*=\s*.*\b(json\.loads|ast\.literal_eval)\s*\(.*\b(response|completion|llm_output|model_output)\b'
    ),
    "Agentic - PII Passed to External Agent": (
        r'(?i)(ssn|social_security|credit_card|passport|dob|date_of_birth)\b.*\b(agent|llm|openai|anthropic|completion)\b'
    ),
}

# ---------------------------------------------------------------------------
# MCP tool poisoning — hidden instructions embedded in a tool's docstring or
# description (the canonical MCP tool-poisoning vector: an LLM reads the
# tool's description/docstring as part of its context and can be hijacked
# by instructions hidden there, invisible to the human calling the tool).
# Consumed by secchecker.llm_scanner._scan_python_docstrings via ast.
# ---------------------------------------------------------------------------

TOOL_POISONING_MARKERS = (
    r'(?is)(?:ignore\s+(?:previous|prior|all)\s+instructions'
    r'|<\s*/?\s*important\s*>'
    r'|do\s+not\s+(?:tell|inform|mention|reveal|show)\s+(?:this\s+to\s+)?the\s+user'
    r'|(?:^|\n)\s*system\s*:'
    r'|disregard\s+(?:your\s+)?(?:system\s+)?prompt)'
)

CAT_POISONED_DOCSTRING = "MCP - Poisoned Tool Docstring"
CAT_POISONED_DESCRIPTION = "MCP - Poisoned Tool Description"

LLM_SEVERITY_MAP: Dict[str, str] = {
    "LLM - Eval of LLM Output": "CRITICAL",
    "LLM - Secret Passed to LLM": "CRITICAL",
    "LLM - OpenAI API Key": "CRITICAL",
    "LLM - Anthropic API Key": "CRITICAL",
    "LLM - Hardcoded Jailbreak Instruction": "HIGH",
    "LLM - Role Override Instruction": "HIGH",
    "LLM - Prompt Injection via f-string": "HIGH",
    "LLM - Prompt Injection via format()": "HIGH",
    "LLM - Prompt Delimiter Injection": "HIGH",
    "LLM - RAG DB Query in Context": "HIGH",
    "LLM - Env Var in LLM Context": "HIGH",
    "LLM - HuggingFace Token": "HIGH",
    "LLM - Pinecone API Key": "HIGH",
    "LLM - Weaviate API Key": "HIGH",
    "LLM - Groq API Key": "HIGH",
    "LLM - OpenRouter API Key": "HIGH",
    "LLM - xAI API Key": "HIGH",
    "LLM - LangSmith API Key": "HIGH",
    "LLM - LangChain Unsafe Input": "MEDIUM",
    "LLM - RAG Raw File in Prompt": "MEDIUM",
    "LLM - API Key in Log Statement": "MEDIUM",
    "LLM - System Prompt Hardcoded": "LOW",

    # MCP / Agentic AI
    "MCP - Tool Call Output Executed Directly": "CRITICAL",
    "Agentic - Function Call Result Not Validated": "CRITICAL",
    "Agentic - PII Passed to External Agent": "CRITICAL",

    "MCP - Unvalidated Tool Result in Prompt": "HIGH",
    "MCP - Hardcoded MCP Server URL": "HIGH",
    "MCP - Untrusted Tool Description in Prompt": "HIGH",
    "Agentic - Unsanitized Input to Agent Memory": "HIGH",
    "Agentic - Recursive Self-Invocation Risk": "HIGH",
    CAT_POISONED_DOCSTRING: "HIGH",
    CAT_POISONED_DESCRIPTION: "HIGH",

    "Agentic - Agent Loop Without Exit Condition": "MEDIUM",
}
