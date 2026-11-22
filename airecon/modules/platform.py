"""platform.py — consolidate platform/technology identification into one verdict.

Runs no new network traffic of its own; it re-reads the root response already
captured by ``passive/headers`` (when present) so the report carries a single
explicit "detected platform" section regardless of which modules ran. When it
has no root response to work from, it fetches the root once (passive).
"""

from __future__ import annotations

from ..core.detect import identify_platform, scan_tech
from ..core.findings import Confidence, Findings

MODULE = "passive/platform"

_CONF = {"confirmed": Confidence.CONFIRMED, "likely": Confidence.LIKELY,
         "possible": Confidence.POSSIBLE}


def run(target: str, http, findings: Findings) -> dict:
    # Find a root exchange if headers module already fetched one (prefer the
    # post-redirect response when a login redirect was followed).
    root = None
    for label in ("headers:root-redirect", "headers:root"):
        for ex in http.exchanges:
            if ex.label == label and ex.status is not None:
                root = ex
                break
        if root is not None:
            break
    if root is None:
        url = target if target.startswith("http") else "https://" + target
        root = http.get(url.rstrip("/") + "/", label="platform:root")
        if root.status is None:
            findings.add_simple(MODULE, "Platform check skipped",
                                f"Root not reachable: {root.error}", Confidence.INFO)
            return {"platform": None}

    headers = root.response_headers or {}
    body = root.response_body or ""
    verdict = identify_platform(headers, body)

    if verdict.platform:
        findings.add_simple(
            MODULE, f"Detected AI platform: {verdict.platform}",
            f"Confidence: {verdict.confidence}. Evidence: " + "; ".join(verdict.reasons),
            _CONF.get(verdict.confidence, Confidence.POSSIBLE),
            data={"platform": verdict.platform, "confidence": verdict.confidence,
                  "reasons": verdict.reasons},
            tags=["platform", "summary"],
        )
    else:
        findings.add_simple(
            MODULE, "Detected AI platform: none identified",
            "No known AI platform signature matched the public response. "
            "This is an absence of evidence, not evidence of absence — the app "
            "may still be AI-powered behind an unrecognised front end.",
            Confidence.INFO, tags=["platform", "summary"],
        )

    # Summarise the tech stack that was observed
    tech = scan_tech(headers, body)
    comps = sorted({m.component for m in tech})
    if comps:
        findings.add_simple(
            MODULE, "Observed technology stack",
            ", ".join(comps), Confidence.LIKELY,
            data={"technologies": comps}, tags=["technology", "summary"],
        )
    return {"platform": verdict.platform, "confidence": verdict.confidence,
            "technologies": comps}
