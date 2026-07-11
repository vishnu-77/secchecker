"""
demo/app.py — Intentionally vulnerable LangChain/OpenAI app.

This file exists to demonstrate what secchecker catches.
Run: secchecker demo/ --type all

DO NOT deploy this code. Every vulnerability below is intentional.
"""

from fastapi import FastAPI, Request

# [CRITICAL] LLM - OpenAI API Key hardcoded in source
OPENAI_API_KEY = "sk-aBcDeFgHiJkLmNoPqRsTuVwXyZaBcDeFgHiJkLmNoPqRsTuV"

app = FastAPI()


@app.post("/chat")
async def chat(request: Request):
    body = await request.json()
    user_input = body.get("message", "")

    # [HIGH] LLM - Prompt Injection via f-string: user input concatenated into prompt
    prompt = f"You are a helpful assistant. Answer this: {user_input}"

    response = call_openai(prompt)
    llm_response = response.choices[0].text

    # [CRITICAL] LLM - Eval of LLM Output: executing unvalidated model response
    result = eval(llm_response)

    return {"result": result}


@app.post("/search")
async def search(request: Request):
    import sqlite3

    body = await request.json()
    user_query = body.get("query", "")

    conn = sqlite3.connect("knowledge.db")
    # [HIGH] LLM - RAG Data Leakage: unfiltered DB result fed into model context
    rag_context = conn.execute(f"SELECT content FROM docs WHERE topic='{user_query}'").fetchall()

    context = "\n".join(row[0] for row in rag_context)
    prompt = f"Based on this context: {context}\n\nAnswer: {user_query}"

    return {"answer": call_openai(prompt)}


def call_openai(prompt: str):
    import openai
    openai.api_key = OPENAI_API_KEY
    return openai.Completion.create(model="gpt-3.5-turbo-instruct", prompt=prompt)
