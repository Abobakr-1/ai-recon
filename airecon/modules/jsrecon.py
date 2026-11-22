"""jsrecon.py — client-side JavaScript recon (OSAI 2.3).

AI capabilities are usually embedded in web apps, not on dedicated ports,
so the client bundle is a primary recon surface. This module:
  * extracts <script src> references from the page,
  * fetches each script and greps for API endpoints, assistant config
    objects, feature flags, and hardcoded secrets,
  * flags hidden data-* endpoint attributes in the HTML.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

from ..core.findings import Confidence, Findings
from ..core.http import HttpClient

MODULE = "passive/jsrecon"

SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
DATA_ENDPOINT_RE = re.compile(r"data-endpoint=[\"']([^\"']+)[\"']", re.IGNORECASE)

# Patterns of interest inside JS
JS_PATTERNS: list[tuple[str, str, str]] = [
    (r"(['\"])(/api/[^'\"]+)\1", "api_path", "API path"),
    (r"(['\"])(/v\d[^'\"]*)\1", "api_path", "versioned API path"),
    (r"assistantEndpoint\s*[:=]\s*['\"]([^'\"]+)['\"]", "assistant_endpoint", "assistant endpoint"),
    (r"apiBase\s*[:=]\s*['\"]([^'\"]+)['\"]", "api_base", "API base"),
    (r"featureFlags\s*[:=]\s*\{([^}]*)\}", "feature_flags", "feature flags"),
    (r"(openai|anthropic|google|groq|mistral|cohere)[A-Za-z_]*\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]",
     "possible_key", "possible API key"),
    (r"(sk-[A-Za-z0-9]{20,}|sk-ant-[A-Za-z0-9\-_]{20,}|AIza[0-9A-Za-z\-_]{35})",
     "secret", "hardcoded secret"),
    (r"(gpt-[0-9a-zA-Z.\-]+|claude-[0-9a-zA-Z.\-]+|llama[0-9.\-:]+|qwen[0-9a-zA-Z.\-]*)",
     "model_ref", "model reference"),
]

HIDDEN_ENDPOINT_HINTS = re.compile(r"data-endpoint=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/") + "/"


def run(target: str, http: HttpClient, findings: Findings) -> dict:
    base = _base(target)
    page = http.get(base, label="jsrecon:page")
    if page.status is None:
        findings.add_simple(MODULE, "Page not reachable",
                            f"{base}: {page.error}", Confidence.INFO)
        return {"scripts": []}

    scripts = []
    for m in SCRIPT_RE.finditer(page.response_body or ""):
        src = m.group(1)
        if src.startswith(("data:", "http://", "https://")) and urlparse(src).netloc \
                and urlparse(src).netloc not in urlparse(base).netloc:
            # third-party; still record but do not fetch off-scope
            continue
        scripts.append(urljoin(base, src))

    # hidden endpoints in HTML
    for m in HIDDEN_ENDPOINT_HINTS.finditer(page.response_body or ""):
        findings.add_simple(
            MODULE, "Hidden data-endpoint in page HTML",
            f"Found data-endpoint='{m.group(1)}' in page source",
            Confidence.LIKELY, data={"endpoint": m.group(1)},
            tags=["hidden_endpoint"],
        )

    findings_found = 0
    for js_url in dict.fromkeys(scripts):  # stable dedupe
        ex = http.get(js_url, label=f"jsrecon:script:{urlparse(js_url).path}")
        if ex.status is None or ex.status != 200:
            continue
        body = ex.response_body or ""
        for pattern, category, human in JS_PATTERNS:
            for m in re.finditer(pattern, body, re.IGNORECASE):
                # pick the most specific group
                val = next((g for g in m.groups() if g), m.group(0))
                if category == "api_path":
                    val = m.group(2) if m.lastindex and m.lastindex >= 2 else m.group(0)
                if category == "feature_flags":
                    val = m.group(1)
                findings_found += 1
                conf = Confidence.CONFIRMED if category in ("secret", "assistant_endpoint") \
                    else Confidence.LIKELY
                findings.add_simple(
                    MODULE, f"{human} in {urlparse(js_url).path}",
                    f"{human}: {val}", conf,
                    data={"category": category, "value": val, "script": js_url},
                    tags=["jsrecon", category],
                )
                break  # one per category per script to reduce noise

    if findings_found == 0 and not scripts:
        findings.add_simple(MODULE, "No client JS found",
                            "The page exposes no same-origin scripts; AI "
                            "endpoints may be discovered by other modules.",
                            Confidence.INFO)

    return {"scripts": scripts, "signals": findings_found}
