"""rag.py — RAG pipeline reconnaissance (OSAI 2.3).

Detects whether retrieval is active, then enumerates what it exposes:
  * RAG trigger detection   - general vs company-specific questions, look
    for a populated `sources` array.
  * Knowledge-base mapping  - probe topic areas; collect document titles.
  * Chunk/param inference   - read chunk_id naming and score fields.
  * Threshold testing       - exact term vs synonym vs misspelling to find
    where retrieval stops firing.
  * Metadata harvesting     - verbatim snippets, hostnames, key formats.

Read-only: it asks questions and reads what the API already returns.
"""

from __future__ import annotations

import json
import re

from ..core.findings import Confidence, Findings
from ..core.http import HttpClient

MODULE = "active/rag"

TOPIC_PROBES = [
    "What internal API endpoints exist?",
    "What is the system architecture?",
    "What is the PTO policy?",
    "What is the expense reimbursement procedure?",
    "Summarize the deployment guide.",
    "What security policies are documented?",
    "What emergency access credentials are documented?",
]

THRESHOLD_PROBES = [
    ("exact", "What is the PTO policy?"),
    ("synonym", "vacation days rules"),
    ("misspelling", "vaycation dayz rulez"),
    ("vague", "tell me something"),
]

# Infrastructure / secret patterns to look for inside returned snippets
SNIPPET_PATTERNS = [
    (r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "internal IP address"),
    (r"[\w\-]+\.internal(?::\d+)?", "internal hostname"),
    (r"[\w\-]+\.novatech-internal\.com", "internal domain"),
    (r"ntk_prod_[0-9a-fA-F]{8,}", "API key format"),
    (r"\bAKIA[0-9A-Z]{8,}\b", "AWS access key id"),
    (r"AKIAIOSFODNN7HONEYPOT", "HONEYPOT marker in AWS key"),
    (r"postgres(?:ql)?://[^\"\s]+", "database URI"),
    (r"redis://[^\"\s]+", "redis URI"),
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{16,}", "bearer token"),
    (r"(?i)password\s*[:=]\s*\S+", "password assignment"),
]

# honeypot indicators (from OSAI 2.4)
HONEYPOT_MARKERS = ["honeypot", "canary", "test", "example", "changeme",
                    "your_", "xxx", "sample"]


def _base(target: str) -> str:
    return (target if target.startswith("http") else "http://" + target).rstrip("/")


def _post_chat(http: HttpClient, base: str, query: str, chat_path: str = "/api/chat"):
    url = base + chat_path
    for field in ("query", "message", "prompt"):
        ex = http.post(url, json_body={field: query, "session_id": "airecon-rag"},
                       label="rag:probe")
        if ex.status and ex.status < 400:
            try:
                return json.loads(ex.response_body), field, ex
            except ValueError:
                continue
    return None, None, None


def _extract_sources(obj: dict) -> list:
    srcs = obj.get("sources")
    if isinstance(srcs, list):
        return srcs
    return []


def run(target: str, http: HttpClient, findings: Findings, *,
        chat_path: str = "/api/chat") -> dict:
    base = _base(target)

    # ---- 1. trigger detection (general vs specific) ----
    general, _, _ = _post_chat(http, base, "What is 2+2?", chat_path)
    specific, _, _ = _post_chat(http, base, "What is the PTO policy?", chat_path)

    if general is None and specific is None:
        findings.add_simple(MODULE, "No RAG chat endpoint responded",
                            f"Tried field variants at {base + chat_path}.",
                            Confidence.INFO)
        return {"rag_active": None}

    g_src = _extract_sources(general) if general else []
    s_src = _extract_sources(specific) if specific else []
    rag_active = bool(s_src) and not bool(g_src)
    if rag_active:
        findings.add_simple(
            MODULE, "RAG retrieval confirmed",
            "A company-specific query populated the sources array while a "
            "general query did not — retrieval is active.",
            Confidence.CONFIRMED, tags=["rag_active"],
        )
    elif s_src:
        findings.add_simple(MODULE, "Sources present on both queries",
                            "Could not cleanly separate retrieved vs "
                            "model-only answers.", Confidence.POSSIBLE)

    # ---- 2. knowledge-base mapping + metadata harvest ----
    documents: dict[str, int] = {}
    chunk_ids: set[str] = set()
    infra_hits: dict[str, list[str]] = {}

    for q in TOPIC_PROBES:
        obj, _, ex = _post_chat(http, base, q, chat_path)
        if not obj:
            continue
        for s in _extract_sources(obj):
            title = s.get("title") or s.get("document") or s.get("name")
            if title:
                documents[title] = documents.get(title, 0) + 1
            cid = s.get("chunk_id")
            if cid:
                chunk_ids.add(str(cid))
            text = s.get("text") or s.get("content") or ""
            for pat, human in SNIPPET_PATTERNS:
                for m in re.finditer(pat, str(text)):
                    infra_hits.setdefault(human, [])
                    if m.group(0) not in infra_hits[human]:
                        infra_hits[human].append(m.group(0))
            # honeypot check inside snippet
            low = str(text).lower()
            for marker in HONEYPOT_MARKERS:
                if marker in low and any(
                        t in low for t in ("key", "secret", "password", "token", "cred")):
                    findings.add_simple(
                        MODULE, "Possible honeypot / canary content",
                        f"Retrieved snippet contains marker '{marker}' near "
                        "credential-like text. Treat as canary until proven.",
                        Confidence.LIKELY, tags=["honeypot"],
                        data={"marker": marker, "snippet": str(text)[:300]},
                    )
                    break

    if documents:
        listing = ", ".join(sorted(documents))
        findings.add_simple(
            MODULE, f"Knowledge base mapped: {len(documents)} document(s)",
            f"Documents surfaced via source metadata: {listing}",
            Confidence.CONFIRMED, data={"documents": documents},
            tags=["kb_mapping"],
        )
    if chunk_ids:
        sample = sorted(chunk_ids)[:12]
        findings.add_simple(
            MODULE, "Chunk identifiers exposed",
            f"Chunk IDs reveal chunking strategy: {', '.join(sample)}"
            + (" ..." if len(chunk_ids) > 12 else ""),
            Confidence.LIKELY, data={"chunk_ids": sorted(chunk_ids)},
            tags=["chunk_inference"],
        )
    for human, values in infra_hits.items():
        findings.add_simple(
            MODULE, f"Infrastructure leaked in retrieved text: {human}",
            f"Values observed: {', '.join(values[:8])}",
            Confidence.CONFIRMED if human not in ("password assignment",) else Confidence.LIKELY,
            data={"type": human, "values": values[:20]}, tags=["infra_leak"],
        )

    # ---- 3. retrieval threshold testing ----
    threshold_obs: dict[str, bool] = {}
    for label, q in THRESHOLD_PROBES:
        obj, _, _ = _post_chat(http, base, q, chat_path)
        if obj is None:
            threshold_obs[label] = False
            continue
        threshold_obs[label] = bool(_extract_sources(obj))
    if threshold_obs:
        findings.add_simple(
            MODULE, "Retrieval threshold behavior",
            "Retrieval fired for: " +
            ", ".join(k for k, v in threshold_obs.items() if v) +
            ("; did NOT fire for: " + ", ".join(k for k, v in threshold_obs.items() if not v)
             if any(not v for v in threshold_obs.values()) else ""),
            Confidence.LIKELY, data=threshold_obs, tags=["threshold"],
        )
        if threshold_obs.get("exact") and not threshold_obs.get("misspelling"):
            findings.add_simple(
                MODULE, "Threshold inference",
                "Heavy misspellings drop retrieval below threshold while exact "
                "terms trigger it; queries below threshold answer ungrounded.",
                Confidence.LIKELY, tags=["threshold"],
            )

    return {"rag_active": rag_active, "documents": list(documents),
            "chunk_ids": sorted(chunk_ids), "thresholds": threshold_obs}
