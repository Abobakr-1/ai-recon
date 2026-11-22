"""wellknown.py — fetch files the site itself publishes (passive).

Only requests well-known, publicly-advertised paths (robots.txt, sitemap.xml,
.security.txt, OIDC discovery, AI plugin/agent descriptors). These are files the
operator intends to be fetchable by any anonymous client, so this is passive
collection, not hidden-endpoint probing. It never brute-forces paths.
"""

from __future__ import annotations

from ..core.detect import WELL_KNOWN_FILES
from ..core.findings import Confidence, Findings

MODULE = "passive/wellknown"


def _base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    return target.rstrip("/")


def _looks_like_spa_html(body: str, content_type: str) -> bool:
    """True when a ``.well-known`` path returned the single-page-app shell.

    Many sites serve index.html for unknown paths (SPA catch-all). A 200 with
    ``text/html`` and ``<!doctype html`` is not a published descriptor; treating
    it as one produces a false positive.
    """
    if "html" not in (content_type or "").lower():
        return False
    head = body[:400].lower()
    return "<!doctype html" in head or "<html" in head


def _looks_like_json_descriptor(body: str) -> bool:
    head = body.lstrip()
    return head.startswith("{") or head.startswith("[")


def run(target: str, http, findings: Findings) -> dict:
    base = _base(target)
    found: list[dict] = []
    for path in WELL_KNOWN_FILES:
        url = base + path
        ex = http.get(url, label=f"wellknown:{path}")
        if ex.status is None or ex.status >= 400:
            continue
        body = (ex.response_body or "").strip()
        ctype = ex.response_headers.get("Content-Type", "")
        if not body:
            continue
        # Reject SPA catch-all HTML served for a descriptor path.
        is_spa = _looks_like_spa_html(body, ctype)
        if is_spa and path not in ("/robots.txt", "/sitemap.xml"):
            continue
        found.append({"path": path, "status": ex.status, "size": len(body),
                      "content_type": ctype})
        # robots.txt is worth surfacing specially
        if path == "/robots.txt":
            findings.add_simple(
                MODULE, "robots.txt published",
                body[:600], Confidence.CONFIRMED,
                data={"url": url, "content": body[:2000]}, tags=["wellknown", "robots"],
            )
        elif path == "/sitemap.xml":
            findings.add_simple(
                MODULE, "sitemap.xml published",
                f"{len(body)} bytes; first URL(s): " +
                ", ".join(_extract_locs(body)[:5]),
                Confidence.CONFIRMED, data={"url": url}, tags=["wellknown", "sitemap"],
            )
        elif path == "/.well-known/security.txt":
            findings.add_simple(
                MODULE, "security.txt published",
                body[:500], Confidence.CONFIRMED,
                data={"url": url, "content": body[:2000]}, tags=["wellknown"],
            )
        elif path in ("/.well-known/agent.json", "/.well-known/agent-card.json",
                      "/.well-known/mcp", "/.well-known/ai-plugin.json"):
            # Only meaningful if it is actually a JSON descriptor.
            if not _looks_like_json_descriptor(body):
                continue
            findings.add_simple(
                MODULE, f"Agent/MCP descriptor published at {path}",
                body[:400], Confidence.LIKELY,
                data={"url": url, "content": body[:2000]}, tags=["wellknown", "agent"],
            )

    if not found:
        findings.add_simple(
            MODULE, "No well-known files retrieved",
            "None of the standard published files (robots.txt, sitemap, security.txt, "
            "OIDC discovery, agent descriptors) were reachable.",
            Confidence.INFO,
        )
    return {"found": found}


def _extract_locs(xml: str) -> list[str]:
    import re
    return re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", xml, re.IGNORECASE)
