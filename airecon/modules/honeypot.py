"""honeypot.py — canary / honeypot recognition (OSAI 2.4).

Sophisticated defenders seed AI knowledge bases with fake credentials and
internal URLs. Using those "discovered" secrets reveals the attacker. This
module does NOT use credentials. It only *classifies* credential-shaped
strings surfaced by other modules and flags likely canaries so an operator
never wastes an engagement (or burns OPSEC) on planted bait.
"""

from __future__ import annotations

import re

from ..core.findings import Confidence, Findings

MODULE = "defense/honeypot"

# Markers that betray planted bait
STRONG_MARKERS = ["honeypot", "canary", "tripwire", "dcanary", "sentry"]
SOFT_MARKERS = ["test", "example", "sample", "demo", "changeme", "your_",
                "xxxx", "placeholder", "fake", "dummy", "notreal"]

# Key-shape validators
KEY_SHAPES = [
    (r"AKIA[0-9A-Z]{12,}", "AWS access key id"),
    (r"sk-ant-[A-Za-z0-9\-_]{20,}", "Anthropic key"),
    (r"sk-[A-Za-z0-9]{20,}", "OpenAI-style key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"ghp_[A-Za-z0-9]{20,}", "GitHub token"),
    (r"ntk_prod_[0-9a-fA-F]{8,}", "NovaTech-style key"),
]

# Entropy heuristic: real random secrets have high character diversity.
def _looks_random(s: str) -> bool:
    if len(s) < 12:
        return False
    classes = sum([
        any(c.islower() for c in s),
        any(c.isupper() for c in s),
        any(c.isdigit() for c in s),
        any(not c.isalnum() for c in s),
    ])
    uniq = len(set(s)) / len(s)
    return classes >= 2 and uniq > 0.4


def classify_secret(value: str) -> dict:
    """Return a classification dict for a credential-shaped string."""
    low = value.lower()
    result = {
        "value": value,
        "shape": None,
        "likely_honeypot": False,
        "reasons": [],
    }
    for pat, human in KEY_SHAPES:
        if re.fullmatch(pat, value) or re.search(pat, value):
            result["shape"] = human
            break

    for marker in STRONG_MARKERS:
        if marker in low:
            result["likely_honeypot"] = True
            result["reasons"].append(f"contains strong canary marker '{marker}'")

    # dictionary-word words inside an otherwise random-looking key
    if result["shape"] and not _looks_random(value):
        result["likely_honeypot"] = True
        result["reasons"].append("low entropy / dictionary-like despite key shape")

    for marker in SOFT_MARKERS:
        if marker in low:
            result["reasons"].append(f"contains soft marker '{marker}'")
            if result["likely_honeypot"]:
                continue
            # soft marker alone is only a caution, not a verdict
    return result


def run(target: str, http, findings: Findings, *, values: list[str] | None = None) -> dict:
    """Classify any secret-shaped values already collected by other modules.

    If no values are supplied, this module scans the evidence gathered in the
    findings store (data dicts) for candidate secrets.
    """
    candidates: list[str] = list(values or [])

    # Harvest credential-shaped strings from prior findings
    for f in findings:
        blob = jsonish(f.data)
        for pat, _ in KEY_SHAPES:
            for m in re.finditer(pat, blob):
                candidates.append(m.group(0))

    flagged = 0
    for val in dict.fromkeys(candidates):
        c = classify_secret(val)
        if c["likely_honeypot"]:
            flagged += 1
            findings.add_simple(
                MODULE, "Likely honeypot / canary credential",
                f"Value matches {c['shape'] or 'a key shape'} but is probably "
                f"planted bait: {'; '.join(c['reasons'])}. Do NOT use it.",
                Confidence.LIKELY, data=c, tags=["honeypot"],
            )
        elif c["shape"]:
            findings.add_simple(
                MODULE, f"Credential-shaped string ({c['shape']})",
                "A credential-shaped value surfaced. Verify provenance before "
                "any use; do not test credentials without explicit authorization.",
                Confidence.POSSIBLE, data=c, tags=["secret"],
            )

    if not candidates:
        findings.add_simple(MODULE, "No credential-shaped values to classify",
                            "No secrets were surfaced by the passive/active "
                            "modules.", Confidence.INFO)
    return {"candidates": len(candidates), "flagged_honeypots": flagged}


def jsonish(obj) -> str:
    import json
    try:
        return json.dumps(obj)
    except (TypeError, ValueError):
        return str(obj)
