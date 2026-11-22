"""tls.py — passive TLS/transport collection.

Performs a plain TLS handshake to the target host:port and records the
certificate and negotiated parameters that any TLS client would see. This is
the same information a browser receives when it connects; no vulnerability
probing is performed. If the host has no TLS or the handshake fails, that is
recorded honestly.
"""

from __future__ import annotations

import socket
import ssl
from urllib.parse import urlparse

from ..core.findings import Confidence, Findings

MODULE = "passive/tls"


def collect(host: str, port: int = 443, timeout: float = 10.0) -> dict:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                version = ssock.version()
                cipher = ssock.cipher()
                return {
                    "ok": True,
                    "version": version,
                    "cipher": cipher[0] if cipher else None,
                    "subject": _flatten(cert.get("subject")),
                    "issuer": _flatten(cert.get("issuer")),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san": [v for k, v in cert.get("subjectAltName", []) if k == "DNS"][:30],
                }
    except ssl.SSLCertVerificationError as exc:
        return {"ok": False, "error": f"certificate verification: {exc}"}
    except ssl.SSLError as exc:
        return {"ok": False, "error": f"TLS error: {exc}"}
    except (OSError, socket.timeout) as exc:
        return {"ok": False, "error": f"connection: {exc}"}


def _flatten(rdns) -> str:
    if not rdns:
        return ""
    parts = []
    for rdn in rdns:
        for k, v in rdn:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


def run(target: str, http, findings: Findings) -> dict:
    parsed = urlparse(target if "://" in target else "http://" + target)
    host = parsed.hostname
    scheme = parsed.scheme or "https"
    port = parsed.port or (443 if scheme == "https" else 80)

    res = collect(host, port)
    if not res.get("ok"):
        findings.add_simple(
            MODULE, f"TLS handshake not completed for {host}:{port}",
            res.get("error", "unknown error"),
            Confidence.INFO, data={"host": host, "port": port, "error": res.get("error")},
        )
        return res

    findings.add_simple(
        MODULE, f"TLS certificate for {host}",
        f"subject: {res['subject']}; issuer: {res['issuer']}; "
        f"valid {res['not_before']} -> {res['not_after']}; {res['version']} {res['cipher']}",
        Confidence.CONFIRMED,
        data={k: res[k] for k in ("subject", "issuer", "not_before", "not_after",
                                  "version", "cipher", "san")},
        tags=["tls", "certificate"],
    )

    issuer = (res.get("issuer") or "").lower()
    san = res.get("san") or []
    if san:
        findings.add_simple(
            MODULE, "Certificate SAN hostnames",
            ", ".join(san[:20]) + (" ..." if len(san) > 20 else ""),
            Confidence.INFO, data={"san": san}, tags=["tls", "san"],
        )
    # Issuer is useful for platform inference (e.g. Google Trust Services -> Google)
    if "google trust services" in issuer:
        findings.add_simple(
            MODULE, "Certificate issued by Google Trust Services",
            "Consistent with Google-hosted infrastructure (platform inference only).",
            Confidence.INFO, tags=["tls", "google"],
        )
    elif "cloudflare" in issuer:
        findings.add_simple(
            MODULE, "Certificate issued by Cloudflare",
            "Consistent with Cloudflare-fronted hosting.", Confidence.INFO, tags=["tls"],
        )
    return res
