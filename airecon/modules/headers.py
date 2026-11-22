"""headers.py — passive HTTP header fingerprinting (OSAI 2.2).

Low-interaction: fetch the site root and (optionally) a couple of common
AI-adjacent paths, then run the header/body detection library. This mirrors
the chapter's `curl -I` workflow but structured and evidence-backed.
"""

from __future__ import annotations

from ..core.detect import scan_body, scan_headers
from ..core.findings import Confidence, Findings
from ..core.http import HttpClient

MODULE = "passive/headers"

CONF_MAP = {
    "confirmed": Confidence.CONFIRMED,
    "likely": Confidence.LIKELY,
    "possible": Confidence.POSSIBLE,
}


def _norm_url(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/") + "/"


def run(target: str, http: HttpClient, findings: Findings) -> dict:
    root = _norm_url(target)
    ex = http.head(root, label="headers:root")
    if ex.status is None:
        ex = http.get(root, label="headers:root-get")
    if ex.status is None:
        findings.add_simple(MODULE, "Root not reachable",
                            f"Could not reach {root}: {ex.error}",
                            Confidence.INFO)
        return {"reachable": False}

    # Some servers omit headers on HEAD — fall back to GET.
    if not ex.response_headers:
        ex = http.get(root, label="headers:root-get")

    matches = scan_headers(ex.response_headers)
    matches += scan_body(ex.response_body[:20000])

    # De-duplicate components
    seen: set[tuple[str, str]] = set()
    for m in matches:
        key = (m.component, m.category)
        if key in seen:
            continue
        seen.add(key)
        findings.add_simple(
            MODULE,
            f"{m.component} detected",
            f"{m.where} matched `{m.pattern}` on {root}",
            CONF_MAP.get(m.confidence, Confidence.POSSIBLE),
            data={"component": m.component, "category": m.category,
                  "where": m.where, "pattern": m.pattern},
            evidence=[], tags=[m.category],
        )

    # Explicitly surface the AI-revealing custom headers if present.
    for hk, hv in ex.response_headers.items():
        lk = hk.lower()
        if lk.startswith("x-") and any(
                t in lk for t in ("ai", "llm", "model", "rag", "ml", "agent", "embedding")):
            findings.add_simple(
                MODULE, f"Custom AI header `{hk}`",
                f"{hk}: {hv}", Confidence.CONFIRMED,
                data={"header": hk, "value": hv}, tags=["ai_header"],
            )

    if not matches:
        findings.add_simple(MODULE, "No AI fingerprints in headers/body",
                            "Header/body scan found no known AI component patterns. "
                            "Absence here is not proof none exist.",
                            Confidence.INFO)

    return {
        "reachable": True,
        "status": ex.status,
        "server": ex.response_headers.get("Server", ""),
        "matches": len(matches),
        "url": root,
    }
