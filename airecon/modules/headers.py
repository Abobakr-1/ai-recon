"""headers.py — passive HTTP header & page fingerprinting.

Fetches the target root (and, passively, follows nothing) and runs the
detection library over the response headers, page body and TLS/tech signals.
This is what any anonymous visitor already receives:

  * AI-infrastructure fingerprints (inference servers, gateways, vector DBs).
  * AI platform identification (OpenAI/ChatGPT, Gemini, Claude, ...).
  * Public technology stack indicators.
  * Custom ``X-AI-*`` headers if the operator exposed them.

It does not brute-force paths or send attack payloads.
"""

from __future__ import annotations

from ..core.detect import (find_public_api_hosts, identify_platform,
                           scan_body, scan_headers, scan_tech)
from ..core.findings import Confidence, Findings
from ..core.http import HttpClient

MODULE = "passive/headers"

CONF_MAP = {
    "confirmed": Confidence.CONFIRMED,
    "likely": Confidence.LIKELY,
    "possible": Confidence.POSSIBLE,
}

CHALLENGE_MARKERS = ("cf-mitigated", "just a moment", "attention required",
                     "checking your browser", "challenge-platform",
                     "enable javascript and cookies")


def _is_challenge(headers: dict, body: str) -> bool:
    low_headers = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
    if "cf-mitigated" in low_headers:
        return True
    low_body = (body or "")[:4000].lower()
    return any(m in low_body for m in CHALLENGE_MARKERS)


def _norm_url(target: str, *, passive_default_https: bool = True) -> str:
    if not target.startswith(("http://", "https://")):
        target = ("https://" if passive_default_https else "http://") + target
    return target.rstrip("/") + "/"


def run(target: str, http: HttpClient, findings: Findings) -> dict:
    root = _norm_url(target)
    ex = http.get(root, label="headers:root")
    if ex.status is None:
        findings.add_simple(MODULE, "Root not reachable",
                            f"Could not reach {root}: {ex.error}",
                            Confidence.INFO)
        return {"reachable": False}

    # Follow a single same-host redirect (e.g. claude.ai -> /login) so the
    # real landing page is what we fingerprint — still passive.
    from urllib.parse import urlparse
    if ex.status in (301, 302, 303, 307, 308):
        loc = ex.response_headers.get("Location", "")
        if loc:
            from urllib.parse import urljoin
            abs_loc = urljoin(root, loc)
            if urlparse(abs_loc).hostname == urlparse(root).hostname:
                ex = http.get(abs_loc, label="headers:root-redirect")

    headers = ex.response_headers or {}
    body = ex.response_body or ""
    ctype = (headers.get("Content-Type", "") or "").lower()

    # Access challenges (WAF / bot protection) limit passive observability and
    # must be reported, never guessed around.
    if _is_challenge(headers, body):
        findings.add_simple(
            MODULE, "Access challenge presented (limited passive observability)",
            "The target returned a bot-protection challenge "
            f"(HTTP {ex.status}, Server: {headers.get('Server','?')}). Only challenge "
            "metadata is observable; page content, scripts and endpoints are hidden "
            "from anonymous collection. This is a limitation, not a finding.",
            Confidence.CONFIRMED,
            data={"status": ex.status, "server": headers.get("Server", "")},
            tags=["challenge", "limitation"],
        )

    # Body fingerprinting is only meaningful for JSON/descriptor responses.
    # A large text/html SPA shell contains CSS/JS where words like "chroma"
    # (--content-chromatic-channels) or a public bootstrap "provider" field
    # appear — scanning those produces false positives, so we restrict body
    # scans to non-HTML responses and cap the size.
    is_html = "html" in ctype
    matches = scan_headers(headers)
    if not is_html:
        matches += scan_body(body[:200000])
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
            tags=[m.category],
        )

    # --- Explicit X-AI-* headers ---
    for hk, hv in headers.items():
        lk = hk.lower()
        if lk.startswith("x-") and any(
                t in lk for t in ("ai", "llm", "model", "rag", "ml", "agent", "embedding")):
            findings.add_simple(
                MODULE, f"Custom AI header `{hk}`",
                f"{hk}: {hv}", Confidence.CONFIRMED,
                data={"header": hk, "value": hv}, tags=["ai_header"],
            )

    # --- Platform identification ---
    verdict = identify_platform(headers, body, cnames=[])
    if verdict.platform:
        conf = CONF_MAP.get(verdict.confidence, Confidence.POSSIBLE)
        findings.add_simple(
            MODULE, f"AI platform identified: {verdict.platform}",
            "Evidence: " + "; ".join(verdict.reasons),
            conf, data={"platform": verdict.platform, "confidence": verdict.confidence,
                        "reasons": verdict.reasons},
            tags=["platform"],
        )
    else:
        findings.add_simple(
            MODULE, "No known AI platform identified",
            "Public headers/body did not match a known platform signature. "
            "Absence of a match is not evidence the target is not an AI system.",
            Confidence.INFO,
        )

    # --- Technology stack ---
    tech = scan_tech(headers, body)
    tseen: set[str] = set()
    for m in tech:
        if m.component in tseen:
            continue
        tseen.add(m.component)
        findings.add_simple(
            MODULE, f"Technology: {m.component}",
            f"{m.category} indicator via `{m.pattern}`",
            CONF_MAP.get(m.confidence, Confidence.POSSIBLE),
            data={"technology": m.component, "category": m.category},
            tags=["technology", m.category],
        )

    # --- Publicly advertised API hosts found in page text ---
    api_hosts = find_public_api_hosts(body)
    if api_hosts:
        findings.add_simple(
            MODULE, "Publicly referenced API host(s)",
            ", ".join(api_hosts[:15]),
            Confidence.LIKELY, data={"hosts": api_hosts}, tags=["api_endpoint"],
        )

    return {
        "reachable": True,
        "status": ex.status,
        "server": headers.get("Server", ""),
        "platform": verdict.platform,
        "platform_confidence": verdict.confidence,
        "matches": len(matches),
        "url": root,
    }
