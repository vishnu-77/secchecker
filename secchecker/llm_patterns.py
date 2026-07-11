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
    "LLM - OpenAI API Key": r'sk-[a-zA-Z0-9]{48}',
    "LLM - Anthropic API Key": r'sk-ant-[a-zA-Z0-9\-_]{93}',
    "LLM - HuggingFace Token": r'hf_[a-zA-Z0-9]{34,}',
    "LLM - Pinecone API Key": r'(?i)pinecone.*api[_\-]?key[\'"\s:=]+[a-zA-Z0-9\-]{32,}',
    "LLM - Weaviate API Key": r'(?i)weaviate.*api[_\-]?key[\'"\s:=]+[a-zA-Z0-9\-_]{32,}',
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
    "Agentic - Agent Loop Without Exit Condition": (
        r'(?is)while\s+True.*?\.(run|invoke|call|complete)\s*\('
    ),
    "Agentic - Function Call Result Not Validated": (
        r'(?i)(function_call|tool_call|action)\s*=\s*.*\b(json\.loads|ast\.literal_eval)\s*\(.*\b(response|completion|llm_output|model_output)\b'
    ),
    "Agentic - Recursive Self-Invocation Risk": (
        r'(?is)\b(agent|executor|AgentExecutor|ReActAgent)\b.*?\.(run|invoke)\s*\(.*?\b(agent|executor|AgentExecutor|ReActAgent)\b'
    ),
    "Agentic - PII Passed to External Agent": (
        r'(?i)(ssn|social_security|credit_card|passport|dob|date_of_birth)\b.*\b(agent|llm|openai|anthropic|completion)\b'
    ),
}

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

    "Agentic - Agent Loop Without Exit Condition": "MEDIUM",
}
