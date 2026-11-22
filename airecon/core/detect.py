"""Detection engine — pattern libraries for AI-system fingerprinting.

These patterns mirror the enumerable properties enumerated in OSAI Ch2:
inference servers, orchestration frameworks, vector databases, gateways,
and model identities. A match here is a *signal*, mapped to a confidence
level, never a confirmed fact on its own.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# --------------------------------------------------------------------------- #
# HTTP response header / body patterns → component identity
# Each entry: (regex, component, category, confidence)
# --------------------------------------------------------------------------- #

HEADER_FINGERPRINTS: list[tuple[str, str, str, str]] = [
    # --- Inference servers -------------------------------------------------
    (r"^\s*(?:vllm|vllm/[\d.]+)\s*$", "vLLM inference server", "inference_server", "likely"),
    (r"server:\s*vllm", "vLLM inference server", "inference_server", "likely"),
    (r"x-inference-server:\s*vllm", "vLLM inference server", "inference_server", "likely"),
    (r"\bollama\b", "Ollama (local inference)", "inference_server", "possible"),
    (r"server:\s*tgi\b|text-generation-inference|text_generation_inference",
     "HuggingFace TGI", "inference_server", "likely"),
    (r"x-llama|llama\.cpp|llamacpp", "llama.cpp", "inference_server", "possible"),
    (r"server:\s*triton|nvidia triton", "NVIDIA Triton", "inference_server", "likely"),
    (r"x-torchserve|torchserve", "TorchServe", "inference_server", "likely"),
    # --- API gateways ------------------------------------------------------
    (r"server:\s*kong/|x-kong-", "Kong API gateway", "gateway", "confirmed"),
    (r"server:\s*nginx", "nginx", "web_server", "confirmed"),
    (r"server:\s*envoy|x-envoy-", "Envoy proxy", "gateway", "likely"),
    (r"via:\s*1\.1 google|server:\s*esf", "Google Cloud API gateway", "gateway", "likely"),
    (r"server:\s*openresty", "OpenResty (nginx+lua)", "web_server", "confirmed"),
    (r"server:\s*apache", "Apache httpd", "web_server", "confirmed"),
    (r"server:\s*uvicorn", "uvicorn (ASGI)", "web_server", "confirmed"),
    (r"x-powered-by:\s*fastapi|server:\s*uvicorn", "FastAPI", "framework", "likely"),
    # --- Orchestration frameworks -----------------------------------------
    (r"x-langchain|langchain", "LangChain", "orchestration", "possible"),
    (r"x-framework:\s*langgraph|langgraph", "LangGraph", "orchestration", "possible"),
    (r"x-framework:\s*crewai|crewai", "CrewAI", "orchestration", "possible"),
    (r"autogen|ag2", "AutoGen", "orchestration", "possible"),
    (r"llamaindex|llama_index", "LlamaIndex", "orchestration", "possible"),
    (r"haystack", "Haystack", "orchestration", "possible"),
    (r"semantic-kernel|semantickernel", "Semantic Kernel", "orchestration", "possible"),
    # --- AI-specific custom headers ---------------------------------------
    (r"x-ai-backend:", "custom AI backend header", "ai_header", "confirmed"),
    (r"x-rag-provider:", "custom RAG provider header", "ai_header", "confirmed"),
    (r"x-model-name:|x-model:", "model identity header", "ai_header", "likely"),
    (r"x-llm-|x-model-", "LLM-related custom header", "ai_header", "possible"),
]

# Body / JSON key patterns (health endpoints, error messages, chat responses)
BODY_FINGERPRINTS: list[tuple[str, str, str, str]] = [
    (r'"provider"\s*:\s*"ollama"', "Ollama provider field leak", "provider_leak", "confirmed"),
    (r'"provider"\s*:\s*"(openai|anthropic|google|azure|bedrock|groq)"',
     "Cloud provider field leak", "provider_leak", "confirmed"),
    (r'"model"\s*:\s*"[^"]+"', "model identifier in response", "model_leak", "confirmed"),
    (r'"llama[\d.\-]', "Llama family model", "model_family", "likely"),
    (r'"qwen', "Qwen family model", "model_family", "likely"),
    (r'"mistral|mixtral', "Mistral family model", "model_family", "likely"),
    (r'"gemma', "Gemma family model", "model_family", "likely"),
    (r'"claude', "Anthropic Claude", "model_family", "likely"),
    (r'"gpt-[\d.]|gpt-4o|gpt-3\.5', "OpenAI GPT family", "model_family", "likely"),
    (r'"gemini', "Google Gemini", "model_family", "likely"),
    (r'"deepseek', "DeepSeek", "model_family", "possible"),
    (r'"command-r|cohere', "Cohere", "model_family", "possible"),
    (r"chromadb|chroma-collection", "ChromaDB vector store", "vector_db", "likely"),
    (r"pinecone", "Pinecone vector store", "vector_db", "likely"),
    (r"milvus", "Milvus vector store", "vector_db", "likely"),
    (r"weaviate", "Weaviate vector store", "vector_db", "likely"),
    (r"qdrant", "Qdrant vector store", "vector_db", "likely"),
    (r"pgvector|vector\(1536\)|vector\(768\)", "pgvector / Postgres embeddings", "vector_db", "possible"),
    (r"faiss", "FAISS index", "vector_db", "possible"),
    (r"redis\.novatech|redis:\d{4}|redis\.internal", "Redis cluster reference", "infra_leak", "possible"),
    (r"vault|hashicorp vault", "HashiCorp Vault reference", "infra_leak", "possible"),
]

# Health/config endpoint keys that reveal AI feature flags
CONFIG_KEYS = [
    "mcp_enabled", "rag_enabled", "model", "provider", "service",
    "version", "status", "features", "tools", "agents",
    "max_tokens", "context_window", "context_length", "embedding_model",
]

# Common AI-carrying URL paths (endpoint enumeration wordlist seed)
COMMON_AI_PATHS = [
    "/api/health", "/api/status", "/api/config", "/api/info", "/api/version",
    "/-/health", "/healthz", "/health", "/readyz", "/status",
    "/api/chat", "/api/v1/chat", "/api/v2/chat", "/api/assistant",
    "/api/v1/assistant", "/api/v2/assistant", "/api/generate", "/api/completion",
    "/api/completions", "/api/embeddings", "/api/embed", "/api/rag",
    "/api/search", "/api/query", "/api/ask", "/api/agent", "/api/agents",
    "/api/tools", "/api/mcp", "/api/models", "/api/v1/models",
    "/v1/chat/completions", "/v1/completions", "/v1/embeddings", "/v1/models",
    "/v2/chat/completions", "/v1/assistant", "/v1/rag", "/v1/query",
    "/chat", "/chat/completions", "/completions", "/generate",
    "/ai", "/ai/chat", "/llm", "/llm/chat", "/assistant", "/agent",
    "/mcp", "/mcp/tools", "/tools", "/.well-known/mcp", "/sse",
    "/.well-known/agent.json", "/.well-known/agent-card.json",
    "/api/v1/agents", "/agents", "/a2a", "/api/a2a",
]

# Endpoint-status semantics for the "401 vs 404" technique
def classify_endpoint_status(status: int) -> str:
    if status in (401, 403):
        return "exists_protected"
    if status == 200:
        return "exists_open"
    if status == 404:
        return "not_found"
    if status in (301, 302, 307, 308):
        return "redirect"
    if status == 405:
        return "exists_wrong_method"
    if status in (500, 502, 503):
        return "exists_erroring"
    return "other"


@dataclass
class Match:
    pattern: str
    component: str
    category: str
    confidence: str
    where: str


def scan_headers(headers: dict[str, str]) -> list[Match]:
    text = "\n".join(f"{k.lower()}: {v}" for k, v in headers.items())
    return _scan(text, HEADER_FINGERPRINTS, "headers")


def scan_body(body: str) -> list[Match]:
    return _scan(body or "", BODY_FINGERPRINTS, "body")


def _scan(text: str, rules: list[tuple[str, str, str, str]], where: str) -> list[Match]:
    out: list[Match] = []
    low = text.lower()
    for pattern, component, category, conf in rules:
        if re.search(pattern, low, re.IGNORECASE | re.MULTILINE):
            out.append(Match(pattern=pattern, component=component,
                             category=category, confidence=conf, where=where))
    return out
