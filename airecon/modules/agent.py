"""agent.py — agent / MCP / A2A surface reconnaissance (OSAI 2.2 & 2.3).

Self-describing protocols advertise their own capabilities, which makes them
prime enumeration targets:
  * MCP  - JSON-RPC; tools/list returns full tool schemas (names, params,
    and descriptions that often leak intent and permission boundaries).
  * A2A  - agent cards (.well-known/agent.json) describing capabilities.

This module performs *reads* of those self-descriptions only. It does not
invoke tools; tool invocation is a state-changing action and is out of scope
for reconnaissance.
"""

from __future__ import annotations

import json

from ..core.findings import Confidence, Findings
from ..core.http import HttpClient

MODULE = "active/agent"

MCP_PATHS = ["/mcp", "/mcp/tools", "/api/mcp", "/sse", "/.well-known/mcp",
             "/mcp/sse", "/rpc"]
A2A_PATHS = ["/.well-known/agent.json", "/.well-known/agent-card.json",
             "/agents", "/api/agents", "/a2a", "/api/a2a"]

# Tool-schema fields that reveal blast radius / permissions
PERMISSION_HINTS = ["read-only", "readonly", "create only", "execute", "delete",
                    "write", "admin", "send", "post_", "approve", "shell", "exec",
                    "shell_exec", "run_command"]


def _base(target: str) -> str:
    return (target if target.startswith("http") else "http://" + target).rstrip("/")


def _try_mcp(http: HttpClient, base: str, findings: Findings) -> list[dict]:
    tools: list[dict] = []
    for path in MCP_PATHS:
        url = base + path
        # MCP over JSON-RPC: tools/list
        rpc = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
        ex = http.post(url, json_body=rpc, label=f"agent:mcp:{path}")
        if ex.status and ex.status < 400 and ex.response_body:
            try:
                obj = json.loads(ex.response_body)
            except ValueError:
                obj = None
            found = _harvest_tools(obj, path, findings)
            if found:
                tools.extend(found)
                findings.add_simple(
                    MODULE, f"MCP server exposed at {path}",
                    f"tools/list returned {len(found)} tool schema(s).",
                    Confidence.CONFIRMED, data={"path": path, "tools": found},
                    tags=["mcp"],
                )
        # Some servers expose an HTTP GET tools listing
        ex2 = http.get(url, label=f"agent:mcp-get:{path}")
        if ex2.status and ex2.status < 400 and ex2.response_body:
            try:
                obj = json.loads(ex2.response_body)
            except ValueError:
                obj = None
            found = _harvest_tools(obj, path, findings)
            for t in found:
                if t not in tools:
                    tools.append(t)
    return tools


def _harvest_tools(obj, path: str, findings: Findings) -> list[dict]:
    if not isinstance(obj, dict):
        return []
    result = obj.get("result", obj)
    tools = None
    if isinstance(result, dict):
        tools = result.get("tools")
    if not tools and isinstance(obj.get("tools"), list):
        tools = obj["tools"]
    if not isinstance(tools, list):
        return []
    out = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        name = t.get("name", "?")
        desc = t.get("description", "") or ""
        out.append({"name": name, "description": desc[:300],
                    "inputSchema": t.get("inputSchema", {})})
        low = (name + " " + desc).lower()
        risky = [h for h in PERMISSION_HINTS if h in low]
        if risky:
            findings.add_simple(
                MODULE, f"MCP tool with elevated capability: {name}",
                f"Tool '{name}' description/schema suggests capability: "
                f"{', '.join(risky)}. Description: {desc[:200]}",
                Confidence.LIKELY, data={"tool": name, "hints": risky},
                tags=["mcp", "capability"],
            )
        # injection-in-metadata signal (untrusted content the model reads)
        if any(k in low for k in ("ignore", "always call", "before returning",
                                   "do not mention", "system prompt")):
            findings.add_simple(
                MODULE, f"MCP tool metadata contains instruction-like text: {name}",
                f"Tool '{name}' description contains imperative/instruction "
                f"phrasing (possible tool-poisoning surface): {desc[:200]}",
                Confidence.POSSIBLE, data={"tool": name},
                tags=["mcp", "tool_poisoning"],
            )
    return out


def _try_a2a(http: HttpClient, base: str, findings: Findings) -> list[dict]:
    cards: list[dict] = []
    for path in A2A_PATHS:
        ex = http.get(base + path, label=f"agent:a2a:{path}")
        if not ex.status or ex.status >= 400 or not ex.response_body:
            continue
        try:
            obj = json.loads(ex.response_body)
        except ValueError:
            continue
        if isinstance(obj, dict) and ("name" in obj or "capabilities" in obj
                                      or "skills" in obj):
            cards.append({"path": path, "card": obj})
            findings.add_simple(
                MODULE, f"A2A agent card exposed at {path}",
                f"Agent self-description: name={obj.get('name', '?')}, "
                f"capabilities={list(obj.get('capabilities', {}))[:8]}",
                Confidence.CONFIRMED, data={"path": path, "card": obj},
                tags=["a2a"],
            )
    return cards


def run(target: str, http: HttpClient, findings: Findings) -> dict:
    base = _base(target)
    tools = _try_mcp(http, base, findings)
    cards = _try_a2a(http, base, findings)
    if not tools and not cards:
        findings.add_simple(
            MODULE, "No self-describing agent surface found",
            "No MCP tools/list or A2A agent card was reachable. Absence is "
            "not proof none exist — try non-standard paths or auth'd routes.",
            Confidence.INFO,
        )
    return {"mcp_tools": tools, "a2a_cards": cards}
