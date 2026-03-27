"""LLM/AI Security patterns for detecting vulnerabilities in LLM application code."""
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
}
