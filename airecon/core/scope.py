"""Scope guard.

A tool that probes AI systems must fail closed. This module is the single
choke point: every active request path in airecon calls ``Scope.authorize()``
before touching the network. If the target host is not in the configured
allow-list, the request is refused by default.

This mirrors the discipline in the OSAI material and the wider engagement
rule: authorization is per-asset and per-action, and reachability is not
authorization. You must explicitly declare what you are allowed to test.
"""

from __future__ import annotations

import fnmatch
import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeError(RuntimeError):
    """Raised when a target is not authorized by the active scope."""


@dataclass
class Scope:
    """An explicit allow-list of hosts/CIDRs you are authorized to test."""

    allow: list[str] = field(default_factory=list)
    # When True, private/loopback/link-local targets are permitted without an
    # explicit allow entry. Useful for your own labs, never for real targets.
    allow_private: bool = False
    deny: list[str] = field(default_factory=list)
    note: str = ""

    # ------------------------------------------------------------------ #
    def _host_matches(self, host: str, entry: str) -> bool:
        host = host.lower().strip("[]")
        entry = entry.lower().strip()
        if not entry:
            return False
        # CIDR / bare IP
        try:
            net = ipaddress.ip_network(entry, strict=False)
            try:
                return ipaddress.ip_address(host) in net
            except ValueError:
                return False
        except ValueError:
            pass
        # exact host or glob (e.g. *.example.com)
        return fnmatch.fnmatch(host, entry)

    def is_private(self, host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in ("localhost",) or host.endswith(".local")
        return ip.is_private or ip.is_loopback or ip.is_link_local

    # ------------------------------------------------------------------ #
    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason). Pure predicate, no side effects."""
        host = urlparse(target).hostname if "://" in target else target
        if not host:
            return False, "could not parse host from target"

        for entry in self.deny:
            if self._host_matches(host, entry):
                return False, f"host {host} matches explicit DENY entry '{entry}'"

        for entry in self.allow:
            if self._host_matches(host, entry):
                return True, f"host {host} matches allow entry '{entry}'"

        if self.allow_private and self.is_private(host):
            return True, f"host {host} is private/loopback and allow_private is set"

        return False, (
            f"host '{host}' is NOT in scope. Add it explicitly with "
            f"`airecon scope --allow {host}` (or --allow-private for your own lab)."
        )

    def authorize(self, target: str) -> str:
        """Raise ScopeError if not allowed; else return the target unchanged."""
        allowed, reason = self.check(target)
        if not allowed:
            raise ScopeError(reason)
        return target

    # ------------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            allow=list(data.get("allow", []) or []),
            allow_private=bool(data.get("allow_private", False)),
            deny=list(data.get("deny", []) or []),
            note=str(data.get("note", "")),
        )

    def to_dict(self) -> dict:
        return {
            "allow": self.allow,
            "allow_private": self.allow_private,
            "deny": self.deny,
            "note": self.note,
        }
