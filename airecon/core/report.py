"""Reporting: render Findings to Markdown and JSON.

The report deliberately mirrors a bug-bounty recon deliverable: target,
scope, coverage, findings grouped by confidence, and an explicit "what was
not tested" section. It never states an impact that was not demonstrated.
"""

from __future__ import annotations

import datetime as _dt
import json
from pathlib import Path

from .findings import Confidence, Findings

CONF_HEADERS = {
    Confidence.CONFIRMED: "## Confirmed",
    Confidence.LIKELY: "## Likely",
    Confidence.POSSIBLE: "## Possible (needs corroboration)",
    Confidence.INFO: "## Informational",
}


def _now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")


def render_markdown(target: str, findings: Findings, *,
                    scope_note: str = "", coverage: dict | None = None,
                    not_tested: list[str] | None = None,
                    tool_version: str = "1.1.0") -> str:
    lines: list[str] = []
    lines.append(f"# AI RECON recon report")
    lines.append("")
    lines.append(f"- **Target:** `{target}`")
    lines.append(f"- **Generated (UTC):** {_now()}")
    lines.append(f"- **Tool:** AI RECON (ai-recon) v{tool_version}")
    if scope_note:
        lines.append(f"- **Scope note:** {scope_note}")
    lines.append("")
    lines.append("> This report mixes two kinds of entry. **Observations** are "
                 "informational facts collected passively (headers, DNS, TLS, "
                 "public JS, platform/tech identifiers); they carry a confidence "
                 "level and are *not* vulnerabilities by themselves. A finding "
                 "becomes a **security issue** only when a broken trust boundary "
                 "is demonstrated — which this reconnaissance tool does not do. "
                 "Read the confidence field on every item.")
    lines.append("")

    if coverage:
        lines.append("## Coverage")
        for k, v in coverage.items():
            lines.append(f"- {k}: {v}")
        lines.append("")

    counts = {c: len(findings.by_confidence(c)) for c in Confidence}
    # by_confidence is cumulative; compute exact buckets instead
    exact = {c: 0 for c in Confidence}
    for f in findings:
        exact[f.confidence] += 1
    lines.append("## Summary")
    for c in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.POSSIBLE, Confidence.INFO):
        lines.append(f"- {c.value}: {exact[c]}")
    lines.append("")

    for c in (Confidence.CONFIRMED, Confidence.LIKELY, Confidence.POSSIBLE, Confidence.INFO):
        items = [f for f in findings if f.confidence == c]
        if not items:
            continue
        lines.append(CONF_HEADERS[c])
        lines.append("")
        for f in items:
            lines.append(f"### [{f.module}] {f.title}")
            if f.detail:
                lines.append("")
                lines.append(f.detail)
            if f.impact:
                lines.append("")
                lines.append(f"**Demonstrated impact:** {f.impact}")
            if f.tags:
                lines.append("")
                lines.append(f"_tags: {', '.join(f.tags)}_")
            if f.evidence:
                lines.append("")
                lines.append("Evidence:")
                for e in f.evidence:
                    lines.append(f"- `{e}`")
            lines.append("")

    if not_tested:
        lines.append("## Not tested / coverage limits")
        for n in not_tested:
            lines.append(f"- {n}")
        lines.append("")

    return "\n".join(lines)


def write_report(outdir: Path, target: str, findings: Findings, **kw) -> dict:
    outdir.mkdir(parents=True, exist_ok=True)
    md = render_markdown(target, findings, **kw)
    (outdir / "report.md").write_text(md, encoding="utf-8")
    payload = {
        "target": target,
        "generated_utc": _now(),
        "tool": "AI RECON",
        "tool_version": kw.get("tool_version", "1.1.0"),
        "findings": findings.to_list(),
    }
    (outdir / "findings.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"markdown": str(outdir / "report.md"), "json": str(outdir / "findings.json")}
