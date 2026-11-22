"""repomine.py — AI source-repository mining (OSAI 2.2 passive).

Given a local clone (or a git URL you are authorized to read), extract the
AI-specific artifacts the chapter calls out:
  * dependency manifests  -> cloud vs self-hosted architecture
  * RAG configs           -> embedding model, chunk size, vector store
  * agent tool definitions -> framework + permission boundaries
  * system prompts        -> persona + restrictions
  * guardrail configs     -> blocked topics + regexes
  * deployment/env         -> provider keys, model fallback chains

Read-only. No network. Operates on a directory path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..core.findings import Confidence, Findings

MODULE = "passive/repomine"

DEP_FILES = ["requirements.txt", "pyproject.toml", "package.json",
             "Pipfile", "environment.yml", "poetry.lock", "go.mod"]
CONFIG_GLOBS = ["**/rag*.y*ml", "**/*rag*.yaml", "**/*rag*.yml",
                "**/models.yaml", "**/models.yml", "**/config/*.y*ml",
                "**/safety*.y*ml", "**/*guardrail*", "**/config.yaml",
                "**/.env.example", "**/Modelfile", "**/*Modelfile"]
PROMPT_GLOBS = ["**/prompts/*.txt", "**/prompts/*.md", "**/system.txt",
                "**/system_prompt*", "**/*prompt*.txt", "**/*prompt*.md"]

# Framework fingerprint from dependencies
FRAMEWORK_DEPS = {
    "crewai": "CrewAI", "pyautogen": "AutoGen", "autogen": "AutoGen",
    "langchain": "LangChain", "langgraph": "LangGraph", "llama-index": "LlamaIndex",
    "llamaindex": "LlamaIndex", "haystack": "Haystack", "semantic-kernel": "Semantic Kernel",
    "google-generativeai": "Google Gemini SDK", "google-cloud-aiplatform": "Google Vertex",
    "openai": "OpenAI SDK", "anthropic": "Anthropic SDK", "cohere": "Cohere SDK",
    "vllm": "vLLM inference", "transformers": "HF Transformers", "huggingface-hub": "HF Hub",
    "sentence-transformers": "sentence-transformers", "ollama": "Ollama",
    "pinecone-client": "Pinecone", "pymilvus": "Milvus", "chromadb": "ChromaDB",
    "weaviate-client": "Weaviate", "qdrant-client": "Qdrant", "psycopg2": "PostgreSQL/pgvector",
    "faiss-cpu": "FAISS", "tree-sitter": "tree-sitter AST", "autoawq": "AWQ quant",
    "bitsandbytes": "bitsandbytes quant", "tiktoken": "OpenAI tokenizer",
}


def _read(path: Path, limit: int = 200_000) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:limit]
    except OSError:
        return ""


def run(repo_path: str, findings: Findings) -> dict:
    root = Path(repo_path)
    if not root.exists():
        findings.add_simple(MODULE, "Repository path not found",
                            f"{repo_path} does not exist.", Confidence.INFO)
        return {"found": False}

    # ---- dependencies ----
    deps_found: dict[str, str] = {}
    for name in DEP_FILES:
        for p in root.rglob(name):
            txt = _read(p).lower()
            for dep, human in FRAMEWORK_DEPS.items():
                if dep in txt:
                    deps_found[human] = str(p.relative_to(root))
    if deps_found:
        arch = "cloud-based" if any(
            d in deps_found for d in ("Google Gemini SDK", "OpenAI SDK",
                                       "Anthropic SDK", "Pinecone")) else "self-hosted"
        findings.add_simple(
            MODULE, f"AI stack from dependencies ({arch})",
            "Components: " + ", ".join(sorted(deps_found)),
            Confidence.CONFIRMED, data={"deps": deps_found, "architecture": arch},
            tags=["dependencies", arch],
        )

    # ---- configs ----
    for g in CONFIG_GLOBS:
        for p in root.glob(g):
            if not p.is_file():
                continue
            txt = _read(p)
            low = txt.lower()
            rel = str(p.relative_to(root))
            signals = {}
            for key, pat in (
                ("chunk_size", r"chunk_size\s*:\s*(\d+)"),
                ("chunk_overlap", r"chunk_overlap\s*:\s*(\d+)"),
                ("chunk_strategy", r"strategy\s*:\s*[\"']?([\w_]+)"),
                ("embedding_model", r"model\s*:\s*[\"']([\w/.\-]+)"),
                ("vector_store", r"provider\s*:\s*[\"'](\w+)"),
                ("top_k", r"top_k\s*:\s*(\d+)"),
                ("score_threshold", r"score_threshold\s*:\s*([\d.]+)"),
                ("max_model_len", r"max_model_len\s*:\s*(\d+)"),
                ("inference_server", r"type\s*:\s*[\"']?(\w+)"),
            ):
                m = re.search(pat, txt, re.IGNORECASE)
                if m:
                    signals[key] = m.group(1)
            if signals:
                findings.add_simple(
                    MODULE, f"Config: {rel}",
                    "; ".join(f"{k}={v}" for k, v in signals.items()),
                    Confidence.CONFIRMED, data={"file": rel, "signals": signals},
                    tags=["config", "rag" if "chunk" in str(signals) else "model"],
                )
            # env-style secrets (keys in .env.example are placeholders, note only)
            for m in re.finditer(r"([A-Z0-9_]+_(?:KEY|TOKEN|SECRET|URL))\s*=\s*(\S+)", txt):
                findings.add_simple(
                    MODULE, f"Config variable: {m.group(1)} ({rel})",
                    f"{m.group(1)} is referenced in {rel}. Verify whether the "
                    "value is a placeholder or a live secret.",
                    Confidence.POSSIBLE, data={"file": rel, "var": m.group(1)},
                    tags=["config", "secret_candidate"],
                )
            if "fallback" in low or "chain" in low:
                findings.add_simple(
                    MODULE, f"Model fallback chain referenced in {rel}",
                    "Repository references a model fallback chain — inspect for "
                    "provider order and downgrade paths.",
                    Confidence.POSSIBLE, data={"file": rel}, tags=["config"],
                )

    # ---- tool definitions & prompts ----
    for g in PROMPT_GLOBS + ["**/tools.py", "**/function_schemas.json",
                             "**/tools.json", "**/function*.json"]:
        for p in root.glob(g):
            if not p.is_file():
                continue
            txt = _read(p, 60_000)
            rel = str(p.relative_to(root))
            if "function_schemas" in p.name or p.suffix == ".json":
                try:
                    obj = json.loads(txt)
                    funcs = obj.get("functions", obj.get("tools", [])) \
                        if isinstance(obj, dict) else []
                    names = [f.get("name", "?") for f in funcs if isinstance(f, dict)]
                    if names:
                        findings.add_simple(
                            MODULE, f"Tool schemas: {rel}",
                            f"Defined tools: {', '.join(names)}",
                            Confidence.CONFIRMED, data={"file": rel, "tools": names},
                            tags=["tools"],
                        )
                        for f in funcs:
                            d = (f.get("description", "") or "").lower()
                            if any(h in d for h in ("read-only", "create only",
                                                     "never", "restricted", "allowlist")):
                                findings.add_simple(
                                    MODULE, f"Permission boundary in tool '{f.get('name')}'",
                                    f"Description states: {f.get('description','')[:200]}",
                                    Confidence.LIKELY, data={"file": rel, "tool": f.get("name")},
                                    tags=["permission"],
                                )
                except ValueError:
                    pass
            else:
                # prompt text file: capture restrictions
                if any(k in txt.lower() for k in ("you are", "your role", "restrictions",
                                                   "do not", "never")):
                    snippet = txt.strip()[:400]
                    findings.add_simple(
                        MODULE, f"System prompt: {rel}",
                        snippet, Confidence.CONFIRMED,
                        data={"file": rel, "prompt": snippet}, tags=["prompt"],
                    )

    if not deps_found and len(findings) == 0:
        findings.add_simple(MODULE, "No AI artifacts extracted",
                            "No dependency manifests, RAG configs, tool schemas "
                            "or prompts were found under the given path.",
                            Confidence.INFO)
    return {"deps": deps_found}
