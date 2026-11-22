"""Scope guard — separates passive reconnaissance from active testing.

Design:

* **Passive reconnaissance** collects only what a host already publishes to any
  anonymous visitor (DNS, TLS certificate, HTTP headers, page/JS text, robots,
  sitemap). It is *not* attack traffic, so it is allowed against publicly
  reachable hosts without an allow-list. An explicit ``deny`` entry is still
  honoured.

* **Active reconnaissance / full assessment** sends probes derived from an
  attack hypothesis (endpoint enumeration, fingerprint prompt sets, RAG probing,
  agent/MCP enumeration). It **fails closed**: the host must be named in an
  explicit authorization scope, supplied with ``--scope <file>`` (or an
  allow-list entry), or the run is refused.

The active/full path is never bypassable via a command-line flag. There is no
``--no-scope`` switch; authorization must be asserted deliberately and can be
audited from a file that carries the operator's name and a note.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from urllib.parse import urlparse


class ScopeError(RuntimeError):
    """Raised when a target is not authorized for the requested mode."""


class Mode(str, Enum):
    """Reconnaissance mode, which determines the authorization requirement."""

    PASSIVE = "passive"   # what any anonymous visitor can already see
    ACTIVE = "active"     # hypothesis-driven probing — requires authorization
    FULL = "full"         # passive + active + evasion — requires authorization


@dataclass
class Decision:
    """The outcome of an authorization check."""

    allowed: bool
    reason: str
    mode: Mode

    def __bool__(self) -> bool:  # convenience: `if decision:`
        return self.allowed


@dataclass
class Scope:
    """An explicit allow-list of hosts/CIDRs you are authorized to test."""

    allow: list[str] = field(default_factory=list)
    # When True, private/loopback/link-local targets are permitted for ACTIVE
    # testing without an explicit allow entry. Useful for your own lab.
    allow_private: bool = False
    deny: list[str] = field(default_factory=list)
    note: str = ""
    # Free-text operator assertion recorded alongside the scope file.
    authorized_by: str = ""

    # ------------------------------------------------------------------ #
    # host matching helpers
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

    @staticmethod
    def is_private(host: str) -> bool:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in ("localhost",) or host.endswith(".local")
        return ip.is_private or ip.is_loopback or ip.is_link_local

    @staticmethod
    def _host_of(target: str) -> str:
        return (urlparse(target).hostname if "://" in target else target) or ""

    def is_denied(self, target: str) -> tuple[bool, str]:
        host = self._host_of(target)
        for entry in self.deny:
            if self._host_matches(host, entry):
                return True, f"host {host} matches explicit DENY entry '{entry}'"
        return False, ""

    # ------------------------------------------------------------------ #
    # active / full authorization (fail closed) — original semantics
    # ------------------------------------------------------------------ #
    def check(self, target: str) -> tuple[bool, str]:
        """Return (allowed, reason) for ACTIVE testing. Pure predicate."""
        host = self._host_of(target)
        if not host:
            return False, "could not parse host from target"

        denied, reason = self.is_denied(target)
        if denied:
            return False, reason

        for entry in self.allow:
            if self._host_matches(host, entry):
                return True, f"host {host} matches allow entry '{entry}'"

        if self.allow_private and self.is_private(host):
            return True, f"host {host} is private/loopback and allow_private is set"

        return False, (
            f"host '{host}' is NOT authorized for active testing. Supply an "
            f"authorization scope with `--scope <file>` (see `ai-recon scope "
            f"--help`), or add `--allow {host}` for an asset you are permitted "
            f"to test. Passive recon needs no allow-list: `ai-recon passive {target}`."
        )

    def authorize(self, target: str) -> str:
        """Raise ScopeError if not allowed for active testing."""
        allowed, reason = self.check(target)
        if not allowed:
            raise ScopeError(reason)
        return target

    # ------------------------------------------------------------------ #
    # mode-aware decision (the single entry point used by the HTTP client)
    # ------------------------------------------------------------------ #
    def decide(self, target: str, mode: Mode | str) -> Decision:
        """Decide whether ``target`` may be contacted in ``mode``."""
        mode = Mode(mode)
        host = self._host_of(target)
        if not host:
            return Decision(False, "could not parse host from target", mode)

        # An explicit deny always wins.
        denied, reason = self.is_denied(target)
        if denied:
            return Decision(False, reason, mode)

        if mode is Mode.PASSIVE:
            return Decision(
                True,
                f"passive reconnaissance of publicly reachable host '{host}'",
                mode,
            )

        ok, reason = self.check(target)
        return Decision(ok, reason, mode)

    def allows(self, target: str, mode: Mode | str = Mode.ACTIVE) -> bool:
        return self.decide(target, mode).allowed

    # ------------------------------------------------------------------ #
    # (de)serialization
    # ------------------------------------------------------------------ #
    @classmethod
    def from_dict(cls, data: dict) -> "Scope":
        return cls(
            allow=list(data.get("allow", []) or []),
            allow_private=bool(data.get("allow_private", False)),
            deny=list(data.get("deny", []) or []),
            note=str(data.get("note", "")),
            authorized_by=str(data.get("authorized_by", "")),
        )

    def to_dict(self) -> dict:
        return {
            "allow": self.allow,
            "allow_private": self.allow_private,
            "deny": self.deny,
            "note": self.note,
            "authorized_by": self.authorized_by,
        }

    @classmethod
    def from_file(cls, path: str | Path) -> "Scope":
        """Load a scope from a YAML/JSON mapping, or from a plain host list.

        Detection is based on the first *meaningful* line (comments and blank
        lines stripped), so a YAML file that begins with comments is still
        parsed as YAML. This matters for safety: if a mapping were ever parsed
        as a host list, its ``deny:`` values would be misread as ``allow``
        entries and the deny would be silently dropped.
        """
        p = Path(path)
        if not p.exists():
            raise ScopeError(f"scope file not found: {p}")
        text = p.read_text(encoding="utf-8", errors="replace")

        # First non-comment, non-blank line decides the format.
        first = ""
        for line in text.splitlines():
            stripped = line.split("#", 1)[0].strip()
            if stripped:
                first = stripped
                break

        looks_like_mapping = (
            first.startswith("{")
            or re.match(r"^[A-Za-z_][\w-]*\s*:", first) is not None
        )

        if looks_like_mapping:
            try:
                import yaml  # type: ignore
                data = yaml.safe_load(text)
                if isinstance(data, dict):
                    return cls.from_dict(data)
            except Exception:
                pass
            # A mapping-shaped file that failed to parse must NOT silently fall
            # back to host-list mode (that could turn deny into allow).
            raise ScopeError(
                f"scope file {p} looks like YAML/JSON but could not be parsed. "
                "Fix the syntax, or use a plain host list (one host per line)."
            )

        # Plain host list: one host/glob/CIDR per line.
        hosts: list[str] = []
        for line in text.splitlines():
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            for part in line.replace(",", " ").split():
                hosts.append(part)
        if not hosts:
            raise ScopeError(f"scope file {p} contained no host entries")
        return cls(allow=hosts, note=str(p))

    # ------------------------------------------------------------------ #
    # backward compatible alias
    # ------------------------------------------------------------------ #
    def check_active(self, target: str) -> tuple[bool, str]:
        return self.check(target)
