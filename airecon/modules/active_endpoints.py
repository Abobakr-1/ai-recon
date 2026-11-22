"""active_endpoints.py — active AI endpoint enumeration.

Two techniques combined:
  1. Health/config probing of well-known paths, which often leak model,
     feature flags and versions in JSON.
  2. The "401 vs 404" existence oracle on common AI API paths: a 401/403
     means the route exists but is protected; 404 means absent. This is the
     chapter's endpoint-enumeration method, made structured and paced.
"""

from __future__ import annotations

import json

from ..core.detect import COMMON_AI_PATHS, classify_endpoint_status, scan_body
from ..core.findings import Confidence, Findings
from ..core.http import HttpClient

MODULE = "active/endpoints"

HEALTH_PATHS = ["/api/health", "/api/status", "/api/config", "/api/info",
                "/api/version", "/-/health", "/healthz", "/health", "/readyz"]

CONFIG_KEY_HINTS = ["mcp_enabled", "rag_enabled", "model", "provider",
                    "service", "version", "context_window", "max_tokens",
                    "embedding_model", "tools"]


def _base(target: str) -> str:
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target.rstrip("/")


def run(target: str, http: HttpClient, findings: Findings,
        paths: list[str] | None = None) -> dict:
    base = _base(target)
    paths = paths or COMMON_AI_PATHS

    discovered: list[dict] = []
    health_leaks: list[dict] = []

    for path in paths:
        url = base + path
        ex = http.get(url, label=f"endpoints:{path}")
        if ex.status is None:
            continue
        cls = classify_endpoint_status(ex.status)
        if cls == "not_found":
            continue
        record = {"path": path, "status": ex.status, "class": cls}
        discovered.append(record)

        # Health/config JSON leak detection
        ctype = ex.response_headers.get("Content-Type", "")
        if "json" in ctype.lower() and ex.response_body.strip().startswith(("{", "[")):
            try:
                obj = json.loads(ex.response_body)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                leaked = {k: obj[k] for k in CONFIG_KEY_HINTS if k in obj}
                if leaked:
                    health_leaks.append({"path": path, "data": leaked})
                    findings.add_simple(
                        MODULE, f"Config leak at {path}",
                        f"Endpoint {path} exposes configuration keys: "
                        f"{', '.join(leaked.keys())}",
                        Confidence.CONFIRMED,
                        data={"path": path, "leaked": leaked},
                        tags=["config_leak"],
                    )
            for m in scan_body(ex.response_body[:4000]):
                if m.category in ("model_leak", "provider_leak", "model_family"):
                    findings.add_simple(
                        MODULE, f"{m.component} via {path}",
                        f"Body at {path} matched `{m.pattern}`",
                        Confidence.LIKELY, tags=[m.category],
                        data={"path": path, "pattern": m.pattern},
                    )

    # Classify existence findings
    protected = [d for d in discovered if d["class"] in ("exists_protected",)]
    open_eps = [d for d in discovered if d["class"] == "exists_open"]

    if protected:
        listing = ", ".join(f"{d['path']} ({d['status']})" for d in protected)
        findings.add_simple(
            MODULE, f"{len(protected)} protected AI endpoint(s) discovered",
            f"Routes confirmed to exist (401/403) via the 401-vs-404 oracle: {listing}",
            Confidence.CONFIRMED,
            data={"endpoints": protected}, tags=["endpoint_enum"],
        )
    if open_eps:
        listing = ", ".join(f"{d['path']} ({d['status']})" for d in open_eps)
        findings.add_simple(
            MODULE, f"{len(open_eps)} open endpoint(s) responding 200",
            f"Routes returning 200: {listing}",
            Confidence.LIKELY,
            data={"endpoints": open_eps}, tags=["endpoint_enum"],
        )
    if not discovered:
        findings.add_simple(MODULE, "No AI endpoints discovered",
                            "None of the common AI paths responded. Widen the "
                            "path list or use a target-specific wordlist.",
                            Confidence.INFO)

    return {"checked": len(paths), "discovered": discovered,
            "health_leaks": health_leaks}
