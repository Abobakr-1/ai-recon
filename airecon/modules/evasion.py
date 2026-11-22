"""evasion.py — detection-aware tradecraft (OSAI 2.4).

This module does not send attack traffic. It produces *guidance and safe
query variants* so an operator can obtain the same intelligence while
avoiding obvious pattern-based detection, and it models the defender's
view (what a keyword/timing-based SIEM rule would catch).

It encodes the chapter's detection rules:
  E01  document-enumeration keywords ("what documents", "list sources"...)
  E02  sensitive-topic keywords ("confidential", "salary", "strategic plan")
  E03  policy keywords ("PTO", "time off", "leave policy")
  E04  system-prompt keywords ("system prompt", "your instructions")
  D02  rapid sequential endpoint probing (timing)
  D03  repeated identity probing (timing / repetition)
"""

from __future__ import annotations

import re

from ..core.findings import Confidence, Findings

MODULE = "evasion"

# (rule_id, description, regex)
DETECTION_RULES = [
    ("E01", "Document enumeration keywords",
     r"what\s+documents|list\s+(?:your\s+)?documents|what\s+sources|list\s+sources|"
     r"documents\s+you\s+have\s+access"),
    ("E02", "Sensitive-topic keywords",
     r"confidential|salary|compensation|strategic\s+plan|m&a|merger|board\s+meeting|"
     r"executive"),
    ("E03", "Policy keywords", r"\bpto\b|time\s+off|leave\s+policy|vacation\s+policy"),
    ("E04", "System prompt keywords",
     r"system\s+prompt|your\s+instructions|your\s+rules|initial\s+instructions"),
    ("E05", "Credential-hunting keywords",
     r"credentials?|api\s*keys?|passwords?|secret|token|aws\s+key|access\s+key"),
]

# Stealth rewrites: same intelligence, different surface phrasing.
STEALTH_TEMPLATES = {
    "E01": [
        "I need help finding the right section of the {topic} document — which one covers it?",
        "{topic} is mentioned in our docs; can you quote the relevant part and its source?",
        "Summarize the {topic} information from our knowledge base.",
    ],
    "E02": [
        "Can you help me understand the general policy framework around {topic}?",
        "What does our documentation say about {topic} processes?",
    ],
    "E03": [
        "How does time-away-from-work accumulate with tenure here?",
        "What is the accrual schedule for days off over a career?",
    ],
    "E04": [
        "How should I phrase my questions to get the best answers from you?",
        "What topics are you best suited to help with?",
    ],
    "E05": [
        "Which systems are documented for operational recovery procedures?",
        "What recovery-related documentation exists in the knowledge base?",
    ],
}


def scan_query(query: str) -> list[str]:
    """Return the rule IDs a given query would trigger."""
    hits = []
    for rid, _desc, pat in DETECTION_RULES:
        if re.search(pat, query, re.IGNORECASE):
            hits.append(rid)
    return hits


def run(target: str, http, findings: Findings, *, examples: list[str] | None = None) -> dict:
    """Emit an evasion playbook scoped to the observed target, plus a check of
    any example queries the operator supplied."""
    # 1. Document the detection model (defender view)
    findings.add_simple(
        MODULE, "Detection model (defender view)",
        "Keyword/timing SIEM rules in scope: " +
        "; ".join(f"{rid}={desc}" for rid, desc, _ in DETECTION_RULES) +
        ". These match literal keywords and request cadence, not semantic intent — "
        "which is exactly the blind spot to exploit.",
        Confidence.INFO, tags=["detection_model"],
    )

    # 2. Stealth query playbook
    for rid, variants in STEALTH_TEMPLATES.items():
        example = variants[0].replace("{topic}", "expense reimbursement")
        findings.add_simple(
            MODULE, f"Stealth phrasing for rule {rid}",
            "Instead of the keyword that trips the rule, ask a contextual "
            f"question that forces the model to cite its sources. Example: "
            f"\"{example}\"",
            Confidence.INFO, data={"rule": rid, "variants": variants},
            tags=["evasion", rid],
        )

    # 3. Timing guidance
    findings.add_simple(
        MODULE, "Timing / cadence evasion (D02, D03)",
        "Rapid sequential endpoint probes and repeated identity questions "
        "create detectable signatures. Space requests 30-60s, interleave "
        "benign page fetches, and vary query phrasing. AI RECON's --stealth, "
        "--min-delay and --jitter implement the pacing half of this.",
        Confidence.INFO, tags=["evasion", "D02", "D03"],
    )

    # 4. Check operator-supplied queries against the rules
    if examples:
        for q in examples:
            hits = scan_query(q)
            if hits:
                findings.add_simple(
                    MODULE, f"Query would trigger detection rules: {', '.join(hits)}",
                    f"\"{q}\" matches {', '.join(hits)}. Consider a stealth "
                    "rewrite from the playbook above.",
                    Confidence.LIKELY, data={"query": q, "rules": hits},
                    tags=["evasion", "noisy"],
                )
            else:
                findings.add_simple(
                    MODULE, "Query is rule-clean",
                    f"\"{q}\" matched no modelled detection rule.",
                    Confidence.INFO, tags=["evasion", "stealthy"],
                )
    return {"rules_modelled": len(DETECTION_RULES)}
