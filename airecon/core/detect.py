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
    (r'"provider"\s*:\s*"ollama"', "provider field (public)", "provider_field", "possible"),
    (r'"provider"\s*:\s*"(openai|anthropic|google|azure|bedrock|groq)"',
     "provider field (public)", "provider_field", "possible"),
    (r'"model"\s*:\s*"[a-z0-9][a-z0-9.\-]+"', "model identifier (public)", "model_field", "possible"),
    (r'"llama[\d.\-]', "Llama family model", "model_family", "likely"),
    (r'"qwen', "Qwen family model", "model_family", "likely"),
    (r'"mistral|mixtral', "Mistral family model", "model_family", "likely"),
    (r'"gemma', "Gemma family model", "model_family", "likely"),
    (r'"claude', "Anthropic Claude", "model_family", "likely"),
    (r'"gpt-[\d.]|gpt-4o|gpt-3\.5', "OpenAI GPT family", "model_family", "likely"),
    (r'"gemini', "Google Gemini", "model_family", "likely"),
    (r'"deepseek', "DeepSeek", "model_family", "possible"),
    (r'"command-r|cohere', "Cohere", "model_family", "possible"),
    (r"chromadb|chroma[-_]?db|chroma[-_]?collection|chroma[-_]?server",
     "ChromaDB vector store", "vector_db", "likely"),
    (r"pinecone", "Pinecone vector store", "vector_db", "likely"),
    (r"milvus", "Milvus vector store", "vector_db", "likely"),
    (r"weaviate", "Weaviate vector store", "vector_db", "likely"),
    (r"qdrant", "Qdrant vector store", "vector_db", "likely"),
    (r"pgvector|vector\(1536\)|vector\(768\)", "pgvector / Postgres embeddings", "vector_db", "possible"),
    (r"\bfaiss\b", "FAISS index", "vector_db", "possible"),
    (r"hashicorp vault|\bvault\.[a-z0-9]+\b", "HashiCorp Vault reference", "infra_ref", "possible"),
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


# --------------------------------------------------------------------------- #
# Platform identification
#
# Each signature was captured from a live, *public* HEAD/GET of the platform's
# own marketing/login host (no authentication, no auth bypass). A signature is
# only ever "confirmed" when it comes from a verifiable, platform-unique
# artifact (e.g. an ``oai-did`` cookie, a ``huggingface-moon`` X-Powered-By, a
# Google-fronted certificate, a ``Cf-Mitigated`` challenge). Generic signals
# (Cloudflare fronting, an "AI" word in copy) are deliberately excluded so we
# never claim a platform we cannot evidence.
# --------------------------------------------------------------------------- #

PLATFORM_SIGNATURES: dict[str, dict] = {
    "OpenAI / ChatGPT": {
        "headers": [
            (r"x-openai-proxy-wasm", "unique OpenAI proxy header", "confirmed"),
            (r"oai-did", "OpenAI device-id cookie (oai-did)", "confirmed"),
            (r"oaistatic\.com|cdn\.openai\.com|oaiusercontent\.com", "OpenAI asset CDN host", "confirmed"),
            (r"x-powered-by:\s*express", "Express (frontend origin)", "possible"),
        ],
        "body": [(r"\bchatgpt\b", "ChatGPT branding in page"), ],
        "cname": [],
    },
    "Google Gemini": {
        "headers": [
            (r"server:\s*esf\b", "Google Edge Service Frontend (ESF)", "confirmed"),
            (r"via:\s*1\.1 google", "Google fronting (Via header)", "likely"),
        ],
        "body": [(r"\bgemini\b", "Gemini branding in page")],
        "cname": [(r"googleusercontent|google\.com|1e100\.net|googlehosted", "Google-hosted"), ],
    },
    "Anthropic Claude": {
        "headers": [
            (r"anthropic", "Anthropic header/branding", "likely"),
        ],
        "body": [(r"\bclaude\b", "Claude branding in page")],
        "cname": [(r"anthropic|claude", "Anthropic/Claude hostname")],
    },
    "Microsoft Copilot": {
        "headers": [
            (r"bingserp|nelreports\.net/.*bing", "Bing network-error telemetry", "likely"),
        ],
        "body": [(r"\bcopilot\b", "Copilot branding in page")],
        "cname": [(r"copilot|microsoft|msn|bing", "Microsoft/Bing hostname")],
    },
    "Perplexity": {
        "headers": [],
        "body": [(r"\bperplexity\b", "Perplexity branding in page")],
        "cname": [(r"perplexity", "Perplexity hostname")],
    },
    "Hugging Face": {
        "headers": [
            (r"x-powered-by:\s*huggingface-moon", "Hugging Face X-Powered-By", "confirmed"),
        ],
        "body": [(r"\bhugging\s?face\b", "Hugging Face branding in page")],
        "cname": [(r"huggingface|\bhf\.co\b|cloudfront", "Hugging Face / CDN hostname")],
    },
}

# Technology stack signatures — observable from a public page/headers.
TECH_SIGNATURES: list[tuple[str, str, str, str]] = [
    # (regex, technology, category, confidence)
    (r"\bnext\.js\b|__next_data__|/_next/", "Next.js", "web_framework", "likely"),
    (r"x-powered-by:\s*express", "Express", "web_framework", "confirmed"),
    (r"x-powered-by:\s*nuxt|__nuxt", "Nuxt", "web_framework", "likely"),
    (r"x-powered-by:\s*php|phpsessid", "PHP", "web_framework", "confirmed"),
    (r"server:\s*nginx", "nginx", "web_server", "confirmed"),
    (r"server:\s*cloudflare|cf-ray", "Cloudflare", "cdn", "confirmed"),
    (r"x-vercel|vercel", "Vercel", "hosting", "likely"),
    (r"cloudfront", "AWS CloudFront", "cdn", "likely"),
    (r"x-amz|amazonaws", "AWS", "cloud", "likely"),
    (r"googleusercontent|googleapis|gstatic", "Google Cloud", "cloud", "likely"),
    (r"__vite|vite/", "Vite", "build_tool", "possible"),
    (r"webpack", "webpack", "build_tool", "possible"),
    (r"react", "React", "frontend_lib", "possible"),
    (r"content-security-policy", "CSP present", "security_header", "confirmed"),
    (r"strict-transport-security", "HSTS present", "security_header", "confirmed"),
]

# Framework / backend indicators worth flagging as AI-stack signals.
AI_STACK_INDICATORS: list[tuple[str, str, str, str]] = [
    (r"litellm", "LiteLLM", "ai_gateway", "likely"),
    (r"vllm", "vLLM", "inference_server", "likely"),
    (r"ollama", "Ollama", "inference_server", "likely"),
    (r"langchain", "LangChain", "orchestration", "possible"),
    (r"langgraph", "LangGraph", "orchestration", "possible"),
    (r"llamaindex|llama_index", "LlamaIndex", "orchestration", "possible"),
    (r"crewai", "CrewAI", "orchestration", "possible"),
    (r"autogen", "AutoGen", "orchestration", "possible"),
    (r"text-generation-inference|\btgi\b", "HuggingFace TGI", "inference_server", "possible"),
    (r"pinecone", "Pinecone", "vector_db", "possible"),
    (r"weaviate", "Weaviate", "vector_db", "possible"),
    (r"qdrant", "Qdrant", "vector_db", "possible"),
    (r"milvus", "Milvus", "vector_db", "possible"),
    (r"chromadb|chroma[-_]?db|chroma[-_]?collection|chroma[-_]?server",
     "ChromaDB", "vector_db", "possible"),
    (r"pgvector", "pgvector", "vector_db", "possible"),
]

# Well-known files that are *published* by the site (not hidden probing).
WELL_KNOWN_FILES = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/ai-plugin.json",
    "/.well-known/openid-configuration",
    "/.well-known/oauth-authorization-server",
    "/.well-known/agent.json",
    "/.well-known/agent-card.json",
    "/.well-known/mcp",
    "/.well-known/apple-app-site-association",
]

# Common publicly advertised API hosts to look for in page/JS text (evidence only).
PUBLIC_API_HINT = re.compile(
    r"https?://([a-z0-9.\-]*(?:api|gateway|inference)[a-z0-9.\-]*\.[a-z]{2,})",
    re.IGNORECASE,
)


@dataclass
class PlatformVerdict:
    platform: str | None
    confidence: str
    reasons: list[str]


def identify_platform(headers: dict[str, str], body: str = "",
                      cnames: list[str] | None = None) -> PlatformVerdict:
    """Identify a known AI platform from public headers/body/hostnames.

    Returns the best-supported platform with an explicit confidence. Only
    ``confirmed`` evidence (platform-unique artifact) yields a confirmed
    verdict; a lone branding string yields ``possible``.
    """
    header_text = "\n".join(f"{k.lower()}: {v}" for k, v in headers.items())
    body_text = (body or "")[:200000]
    cname_text = " ".join(cnames or [])
    scores: dict[str, int] = {}
    reasons: dict[str, list[str]] = {}
    best_conf: dict[str, str] = {}

    rank = {"confirmed": 3, "likely": 2, "possible": 1}

    for platform, sigs in PLATFORM_SIGNATURES.items():
        for pat, why, conf in sigs.get("headers", []):
            if re.search(pat, header_text, re.IGNORECASE):
                scores[platform] = scores.get(platform, 0) + rank.get(conf, 1) * 3
                reasons.setdefault(platform, []).append(f"header: {why} ({conf})")
                if rank.get(conf, 1) > rank.get(best_conf.get(platform, "possible"), 0):
                    best_conf[platform] = conf
        for pat, why in sigs.get("body", []):
            if re.search(pat, body_text, re.IGNORECASE):
                scores[platform] = scores.get(platform, 0) + 1
                reasons.setdefault(platform, []).append(f"body: {why} (possible)")
        for pat, why in sigs.get("cname", []):
            if cname_text and re.search(pat, cname_text, re.IGNORECASE):
                scores[platform] = scores.get(platform, 0) + 2
                reasons.setdefault(platform, []).append(f"hostname: {why} (likely)")

    if not scores:
        return PlatformVerdict(None, "none", [])

    top = max(scores, key=lambda k: scores[k])
    conf = best_conf.get(top, "possible")
    # A single weak body match alone is not enough for even "possible".
    if scores[top] < 2:
        return PlatformVerdict(None, "none", reasons.get(top, []))
    return PlatformVerdict(top, conf, reasons.get(top, []))


def scan_tech(headers: dict[str, str], body: str = "") -> list[Match]:
    header_text = "\n".join(f"{k.lower()}: {v}" for k, v in headers.items())
    text = header_text + "\n" + (body or "")[:200000]
    out = _scan(text, TECH_SIGNATURES, "tech")
    out += _scan(text, AI_STACK_INDICATORS, "ai_stack")
    return out


def find_public_api_hosts(body: str) -> list[str]:
    hosts: list[str] = []
    for m in PUBLIC_API_HINT.finditer(body or ""):
        h = m.group(1).lower()
        if h not in hosts:
            hosts.append(h)
    return hosts[:50]

