"""AI RECON CLI — orchestrates the OSAI Ch2 recon methodology.

Usage:
  ai-recon scope --allow 192.168.50.31 [--allow-private] [--save]
  ai-recon passive   <target>
  ai-recon active    <target>
  ai-recon full      <target>
  ai-recon repo      <path>
  ai-recon evasion   <target> [--query "..."]
  ai-recon scan      <target>          # everything network-side
  ai-recon rules     [--query "..."]   # check queries against detection rules

Global options:
  --scope-file PATH   scope config (default ~/.config/ai-recon/scope.yaml)
  --allow HOST        add an allow entry for this run
  --allow-private     permit private/loopback targets (ignore allow-list)
  --min-delay N       seconds between requests (rate-limit respect)
  --jitter N          extra random delay up to N seconds
  --stealth           stealth pacing preset (delay+jitter+decoy hint)
  --out DIR           output directory (default ./airecon-out/<host>)
  --no-evidence       do not write per-request evidence files
  --chat-path PATH    chat endpoint path (default /v1/chat/completions)
  --field NAME        chat body field: messages|query|message
  --timeout N         per-request timeout seconds
  -q/--quiet          less console output
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

from . import __version__, banner
from .core.findings import Confidence, Findings
from .core.http import HttpClient
from .core.report import write_report
from .core.scope import Scope, ScopeError
from .modules import (agent, endpoints, evasion, fingerprint, headers,
                      honeypot, jsrecon, rag, repomine)

DEFAULT_SCOPE_FILE = Path.home() / ".config" / "ai-recon" / "scope.yaml"


# --------------------------------------------------------------------------- #
# scope persistence
# --------------------------------------------------------------------------- #
def load_scope(args) -> Scope:
    scope = Scope()
    if DEFAULT_SCOPE_FILE.exists():
        try:
            data = yaml.safe_load(DEFAULT_SCOPE_FILE.read_text()) or {}
            scope = Scope.from_dict(data)
        except (OSError, yaml.YAMLError):
            pass
    if getattr(args, "allow", None):
        for h in args.allow:
            if h not in scope.allow:
                scope.allow.append(h)
    if getattr(args, "allow_private", False):
        scope.allow_private = True
    return scope


def save_scope(scope: Scope) -> Path:
    DEFAULT_SCOPE_FILE.parent.mkdir(parents=True, exist_ok=True)
    DEFAULT_SCOPE_FILE.write_text(yaml.safe_dump(scope.to_dict(), sort_keys=False),
                                  encoding="utf-8")
    return DEFAULT_SCOPE_FILE


# --------------------------------------------------------------------------- #
# http client construction
# --------------------------------------------------------------------------- #
def build_http(args, scope: Scope, evidence_dir: Path | None) -> HttpClient:
    min_delay = float(getattr(args, "min_delay", 0) or 0)
    jitter = float(getattr(args, "jitter", 0) or 0)
    stealth = bool(getattr(args, "stealth", False))
    if stealth:
        min_delay = max(min_delay, 2.0)
        jitter = max(jitter, 3.0)
    return HttpClient(
        scope=scope,
        min_delay=min_delay,
        jitter=jitter,
        stealth=stealth,
        timeout=float(getattr(args, "timeout", 30) or 30),
        evidence_dir=evidence_dir,
    )


def outdir(args, target: str) -> Path:
    if getattr(args, "out", None):
        return Path(args.out)
    host = urlparse(target if "://" in target else "http://" + target).hostname or "target"
    ts = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path.cwd() / "ai-recon-out" / f"{host}-{ts}"


def _norm(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else "http://" + target


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_scope(args) -> int:
    scope = load_scope(args)
    if args.deny:
        for d in args.deny:
            scope.deny.append(d)
    if args.save:
        p = save_scope(scope)
        print(f"[+] scope saved to {p}")
    print("Active scope:")
    print(yaml.safe_dump(scope.to_dict(), sort_keys=False).rstrip())
    if args.check:
        for t in args.check:
            ok, reason = scope.check(t)
            mark = "ALLOW" if ok else "DENY "
            print(f"  [{mark}] {t}  ({reason})")
    return 0


def _run_passive(target, http, findings):
    headers.run(target, http, findings)
    endpoints.run(target, http, findings)
    jsrecon.run(target, http, findings)


def _run_active(target, http, findings, args):
    fingerprint.run(target, http, findings,
                    chat_path=getattr(args, "chat_path", None),
                    field=getattr(args, "field", None))
    rag.run(target, http, findings)
    agent.run(target, http, findings)
    honeypot.run(target, http, findings)


def _finish(args, target, findings, out: Path, coverage, not_tested, status_note=""):
    info = write_report(out, target, findings, scope_note=status_note,
                        coverage=coverage, not_tested=not_tested,
                        tool_version=__version__)
    exact = {}
    for f in findings:
        exact[f.confidence.value] = exact.get(f.confidence.value, 0) + 1
    if not getattr(args, "quiet", False):
        print()
        print(f"[+] {sum(exact.values())} findings "
              f"(confirmed={exact.get('confirmed',0)}, likely={exact.get('likely',0)}, "
              f"possible={exact.get('possible',0)}, info={exact.get('info',0)})")
        print(f"[+] report: {info['markdown']}")
        print(f"[+] json:   {info['json']}")
        ev = getattr(args, "_evidence", None)
        if ev:
            print(f"[+] evidence: {ev}")
    return 0


def cmd_passive(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)
    out = outdir(args, target)
    evdir = None if args.no_evidence else out / "evidence"
    http = build_http(args, scope, evdir)
    findings = Findings()
    try:
        http.scope.authorize(target)
    except ScopeError as e:
        print(f"[!] scope refusal: {e}", file=sys.stderr)
        return 2
    _run_passive(target, http, findings)
    args._evidence = str(evdir) if evdir else None
    return _finish(args, target, findings, out,
                   coverage={"passive subscribers": "headers, endpoints, jsrecon",
                             "requests": len(http.exchanges)},
                   not_tested=["authenticated endpoints", "active model probing"])


def cmd_active(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)
    out = outdir(args, target)
    evdir = None if args.no_evidence else out / "evidence"
    http = build_http(args, scope, evdir)
    findings = Findings()
    try:
        http.scope.authorize(target)
    except ScopeError as e:
        print(f"[!] scope refusal: {e}", file=sys.stderr)
        return 2
    _run_active(target, http, findings, args)
    args._evidence = str(evdir) if evdir else None
    return _finish(args, target, findings, out,
                   coverage={"active subscribers": "fingerprint, rag, agent, honeypot",
                             "requests": len(http.exchanges)},
                   not_tested=["authenticated-only surfaces",
                               "tool invocation (state-changing, out of recon scope)"])


def cmd_full(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)
    out = outdir(args, target)
    evdir = None if args.no_evidence else out / "evidence"
    http = build_http(args, scope, evdir)
    findings = Findings()
    try:
        http.scope.authorize(target)
    except ScopeError as e:
        print(f"[!] scope refusal: {e}", file=sys.stderr)
        return 2
    _run_passive(target, http, findings)
    _run_active(target, http, findings, args)
    evasion.run(target, http, findings)
    args._evidence = str(evdir) if evdir else None
    return _finish(args, target, findings, out,
                   coverage={"passive": "headers, endpoints, jsrecon",
                             "active": "fingerprint, rag, agent, honeypot",
                             "evasion": "detection model + stealth playbook",
                             "requests": len(http.exchanges)},
                   not_tested=["authenticated-only surfaces",
                               "tool invocation (state-changing)",
                               "exploitation (this tool does recon only)"])


def cmd_repo(args) -> int:
    findings = Findings()
    repomine.run(args.path, findings)
    out = Path(args.out) if args.out else Path.cwd() / "ai-recon-out" / "repo"
    _finish(args, args.path, findings, out,
            coverage={"repo source": args.path},
            not_tested=["runtime behavior", "network surface"],
            status_note="passive repository mining")
    return 0


def cmd_evasion(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)
    out = outdir(args, target)
    http = build_http(args, scope, out / "evidence" if not args.no_evidence else None)
    findings = Findings()
    evasion.run(target, http, findings, examples=args.query)
    args._evidence = None
    return _finish(args, target, findings, out,
                   coverage={"evasion rules modelled": "E01-E05, D02, D03"},
                   not_tested=["live detection confirmation (defender side)"])


def cmd_rules(args) -> int:
    queries = args.query or []
    if not queries:
        print("Modelled detection rules (OSAI 2.4):")
        for rid, desc, pat in evasion.DETECTION_RULES:
            print(f"  {rid}: {desc}")
            print(f"      pattern: {pat}")
        return 0
    rc = 0
    for q in queries:
        hits = evasion.scan_query(q)
        if hits:
            rc = 1
            print(f"[NOISY] {q!r} -> triggers {', '.join(hits)}")
        else:
            print(f"[CLEAN] {q!r} -> no modelled rule matched")
    return rc


# --------------------------------------------------------------------------- #
# parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ai-recon",
        description="AI RECON - AI-system reconnaissance toolkit "
                    "(OSAI Ch2 methodology). Authorized testing only. "
                    "Developed by: AboBakr Mohamed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"AI RECON (ai-recon) {__version__} - "
                           f"Developed by: AboBakr Mohamed")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--allow", action="append", metavar="HOST",
                        help="add an allow entry (repeatable)")
    common.add_argument("--allow-private", action="store_true",
                        help="permit private/loopback targets (own lab)")
    common.add_argument("--min-delay", type=float, default=0.0,
                        help="seconds between requests")
    common.add_argument("--jitter", type=float, default=0.0,
                        help="extra random delay up to N seconds")
    common.add_argument("--stealth", action="store_true",
                        help="stealth pacing preset")
    common.add_argument("--out", metavar="DIR", help="output directory")
    common.add_argument("--no-evidence", action="store_true",
                        help="skip per-request evidence files")
    common.add_argument("--chat-path", default=None,
                        help="chat endpoint path (default /v1/chat/completions)")
    common.add_argument("--field", default=None,
                        help="chat body field: messages|query|message")
    common.add_argument("--timeout", type=float, default=30.0)
    common.add_argument("-q", "--quiet", action="store_true")

    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scope", help="manage the authorization scope")
    sc.add_argument("--allow", action="append", metavar="HOST")
    sc.add_argument("--allow-private", action="store_true")
    sc.add_argument("--deny", action="append", metavar="HOST")
    sc.add_argument("--save", action="store_true")
    sc.add_argument("--check", action="append", metavar="TARGET")
    sc.set_defaults(func=cmd_scope)

    for name, fn, help_ in (("passive", cmd_passive, "passive recon"),
                            ("active", cmd_active, "active recon"),
                            ("full", cmd_full, "passive + active + evasion"),
                            ("evasion", cmd_evasion, "detection/evasion analysis")):
        sp = sub.add_parser(name, parents=[common], help=help_)
        sp.add_argument("target")
        if name == "evasion":
            sp.add_argument("--query", action="append", metavar="Q")
        sp.set_defaults(func=fn)

    rp = sub.add_parser("repo", parents=[common],
                        help="mine a local AI repository (passive)")
    rp.add_argument("path")
    rp.set_defaults(func=cmd_repo)

    rl = sub.add_parser("rules", help="check queries against detection rules")
    rl.add_argument("--query", action="append", metavar="Q")
    rl.set_defaults(func=cmd_rules)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scope":
        return args.func(args)
    if not getattr(args, "quiet", False):
        print(banner())
    try:
        return args.func(args)
    except ScopeError as e:
        print(f"[!] scope refusal: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
