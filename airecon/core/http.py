"""HTTP client with scope enforcement, pacing, and artifact capture.

Wraps ``requests`` but:
  * calls Scope.authorize() before every request (fail-closed),
  * enforces a minimum delay between requests (rate-limit respect),
  * supports "stealth" pacing + jitter + optional decoy requests to blend
    with legitimate traffic (OSAI 2.4 evasion tradecraft),
  * records every exchange to disk as evidence (raw request/response),
  * never logs Authorization headers or obvious secrets to the console.

Only the standard library + requests are required.
"""

from __future__ import annotations

import json
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from .scope import Scope, ScopeError

# Headers that should never be written verbatim into reports/console.
REDACTED_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key",
                    "api-key", "proxy-authorization"}


@dataclass
class Exchange:
    """One request/response pair, retained as evidence."""

    method: str
    url: str
    status: int | None
    request_headers: dict[str, str]
    request_body: str | None
    response_headers: dict[str, str]
    response_body: str
    elapsed_ms: float
    error: str | None = None
    label: str = ""

    def to_dict(self) -> dict:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "request_headers": redact_headers(self.request_headers),
            "request_body": self.request_body,
            "response_headers": self.response_headers,
            "response_body": self.response_body[:8000],
            "elapsed_ms": round(self.elapsed_ms, 1),
            "error": self.error,
            "label": self.label,
        }


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in headers.items():
        if k.lower() in REDACTED_HEADERS:
            out[k] = "<redacted>"
        else:
            out[k] = v
    return out


@dataclass
class HttpClient:
    scope: Scope
    min_delay: float = 0.0          # seconds between requests
    jitter: float = 0.0             # extra random [0, jitter] seconds
    stealth: bool = False           # blend probes with decoy traffic
    timeout: float = 30.0
    user_agent: str = "ai-recon/1.0 (+authorized-recon)"
    verify_tls: bool = True
    max_retries: int = 1
    evidence_dir: Path | None = None
    session: requests.Session = field(default_factory=requests.Session)
    exchanges: list[Exchange] = field(default_factory=list)
    _last_request_ts: float = 0.0

    # ------------------------------------------------------------------ #
    def _pace(self) -> None:
        delay = self.min_delay
        if self.jitter:
            delay += random.uniform(0, self.jitter)
        if delay > 0:
            elapsed = time.monotonic() - self._last_request_ts
            if elapsed < delay:
                time.sleep(delay - elapsed)

    def _maybe_decoy(self) -> None:
        """With stealth on, occasionally fetch a benign sibling path first."""
        if not self.stealth:
            return
        # Not executed automatically here; the engine inserts decoys explicitly
        # so they are visible in evidence. Kept as a hook for module use.
        return

    # ------------------------------------------------------------------ #
    def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: Any | None = None,
        data: Any | None = None,
        label: str = "",
        allow_redirects: bool = False,
    ) -> Exchange:
        self.scope.authorize(url)  # fail closed

        hdrs = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if headers:
            hdrs.update(headers)
        body_repr = None
        if json_body is not None:
            body_repr = json.dumps(json_body)
            hdrs.setdefault("Content-Type", "application/json")
        elif data is not None:
            body_repr = data if isinstance(data, str) else str(data)

        last_err: str | None = None
        for attempt in range(self.max_retries + 1):
            self._pace()
            t0 = time.monotonic()
            try:
                resp = self.session.request(
                    method, url, headers=hdrs, params=params,
                    json=json_body, data=(None if json_body is not None else data),
                    timeout=self.timeout, allow_redirects=allow_redirects,
                    verify=self.verify_tls,
                )
                elapsed = (time.monotonic() - t0) * 1000
                self._last_request_ts = time.monotonic()
                ex = Exchange(
                    method=method.upper(), url=resp.url, status=resp.status_code,
                    request_headers=hdrs, request_body=body_repr,
                    response_headers=dict(resp.headers),
                    response_body=resp.text, elapsed_ms=elapsed,
                    label=label,
                )
                self._record(ex)
                return ex
            except requests.RequestException as exc:
                last_err = f"{type(exc).__name__}: {exc}"
                self._last_request_ts = time.monotonic()
                if attempt < self.max_retries:
                    time.sleep(0.5 * (attempt + 1))
                    continue
        ex = Exchange(
            method=method.upper(), url=url, status=None,
            request_headers=hdrs, request_body=body_repr,
            response_headers={}, response_body="", elapsed_ms=0.0,
            error=last_err, label=label,
        )
        self._record(ex)
        return ex

    def get(self, url: str, **kw) -> Exchange:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> Exchange:
        return self.request("POST", url, **kw)

    def head(self, url: str, **kw) -> Exchange:
        return self.request("HEAD", url, **kw)

    def options(self, url: str, **kw) -> Exchange:
        return self.request("OPTIONS", url, **kw)

    # ------------------------------------------------------------------ #
    def _record(self, ex: Exchange) -> None:
        self.exchanges.append(ex)
        if self.evidence_dir is not None:
            self.evidence_dir.mkdir(parents=True, exist_ok=True)
            fn = self.evidence_dir / f"exchange_{len(self.exchanges):04d}.json"
            try:
                fn.write_text(json.dumps(ex.to_dict(), indent=2), encoding="utf-8")
            except OSError:
                pass
