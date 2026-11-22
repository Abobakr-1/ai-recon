"""AI RECON CLI — universal AI reconnaissance.

Two tiers, split by authorization need:

  PASSIVE  (no allow-list)        publicly observable data any visitor sees:
           DNS, TLS, HTTP headers, page & public JS, well-known files,
           platform/technology detection. Works against any public AI platform.
                 ai-recon passive https://chatgpt.com
                 ai-recon passive https://gemini.google.com

  ACTIVE / FULL  (authorization)  hypothesis-driven probing; FAILS CLOSED
           unless the host is in an explicit authorization scope:
                 ai-recon active https://target.com --scope authorized.txt
                 ai-recon full   https://target.com --scope authorized.txt

Usage:
  ai-recon passive   <url>                       # passive recon (no scope)
  ai-recon active    <url> --scope <file>        # active recon (authorized)
  ai-recon full      <url> --scope <file>        # passive + active + evasion
  ai-recon repo      <path>                      # passive repository mining
  ai-recon evasion   <url> [--query "..."]       # detection/evasion analysis
  ai-recon scope ...                             # manage authorization scope
  ai-recon rules     [--query "..."]             # check queries vs detection rules

Developed by: AboBakr Mohamed
"""

from __future__ import annotations

import argparse
import datetime as _dt
import sys
from pathlib import Path
from urllib.parse import urlparse

import yaml

from . import __version__, banner
from .core.findings import Confidence, Findings
from .core.http import HttpClient
from .core.report import write_report
from .core.scope import Mode, Scope, ScopeError
from .modules import (agent, dns, evasion, fingerprint, headers, honeypot,
                      jsrecon, platform, rag, repomine, tls, wellknown)
from .modules import active_endpoints

DEFAULT_SCOPE_FILE = Path.home() / ".config" / "ai-recon" / "scope.yaml"


# --------------------------------------------------------------------------- #
# scope persistence
# --------------------------------------------------------------------------- #
def load_scope(args) -> Scope:
    scope = Scope()
    # explicit --scope FILE wins
    scope_file = getattr(args, "scope", None)
    if scope_file:
        return Scope.from_file(scope_file)
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
def build_http(args, scope: Scope, mode: Mode, evidence_dir: Path | None) -> HttpClient:
    min_delay = float(getattr(args, "min_delay", 0) or 0)
    jitter = float(getattr(args, "jitter", 0) or 0)
    stealth = bool(getattr(args, "stealth", False))
    if stealth:
        min_delay = max(min_delay, 2.0)
        jitter = max(jitter, 3.0)
    return HttpClient(
        scope=scope,
        mode=mode,
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


def _norm(target: str, *, https: bool = True) -> str:
    if target.startswith(("http://", "https://")):
        return target
    return ("https://" if https else "http://") + target


# --------------------------------------------------------------------------- #
# module groups
# --------------------------------------------------------------------------- #
def _run_passive(target, http, findings):
    dns.run(target, http, findings)
    tls.run(target, http, findings)
    headers.run(target, http, findings)
    jsrecon.run(target, http, findings)
    wellknown.run(target, http, findings)
    platform.run(target, http, findings)


def _run_active(target, http, findings, args):
    active_endpoints.run(target, http, findings)
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
    exact: dict[str, int] = {}
    for f in findings:
        exact[f.confidence.value] = exact.get(f.confidence.value, 0) + 1
    if not getattr(args, "quiet", False):
        print()
        print(f"[+] {sum(exact.values())} observations "
              f"(confirmed={exact.get('confirmed',0)}, likely={exact.get('likely',0)}, "
              f"possible={exact.get('possible',0)}, info={exact.get('info',0)})")
        print(f"[+] report: {info['markdown']}")
        print(f"[+] json:   {info['json']}")
        ev = getattr(args, "_evidence", None)
        if ev:
            print(f"[+] evidence: {ev}")
    return 0


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #
def cmd_scope(args) -> int:
    scope = load_scope(args)
    if args.deny:
        scope.deny.extend(args.deny)
    if getattr(args, "note", None):
        scope.note = args.note
    if getattr(args, "authorized_by", None):
        scope.authorized_by = args.authorized_by
    if args.save:
        p = save_scope(scope)
        print(f"[+] authorization scope saved to {p}")
    print("Active authorization scope (required for active/full only):")
    print(yaml.safe_dump(scope.to_dict(), sort_keys=False).rstrip())
    if args.check:
        for t in args.check:
            d = scope.decide(t, Mode.ACTIVE)
            print(f"  [{'ALLOW' if d.allowed else 'DENY '}] active  {t}  ({d.reason})")
    return 0


def cmd_passive(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)  # only used to honour explicit deny
    out = outdir(args, target)
    evdir = None if args.no_evidence else out / "evidence"
    http = build_http(args, scope, Mode.PASSIVE, evdir)
    findings = Findings()
    # passive: allowed for public hosts; an explicit deny still refuses
    decision = scope.decide(target, Mode.PASSIVE)
    if not decision.allowed:
        print(f"[!] refused: {decision.reason}", file=sys.stderr)
        return 2
    _run_passive(target, http, findings)
    args._evidence = str(evdir) if evdir else None
    return _finish(args, target, findings, out,
                   coverage={"mode": "passive (no authorization required)",
                             "modules": "dns, tls, headers, jsrecon, wellknown, platform",
                             "requests": len(http.exchanges)},
                   not_tested=["authenticated surfaces",
                               "active endpoint enumeration (use `active`)",
                               "model/RAG/agent probing (use `active`)"])


def cmd_active(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)
    out = outdir(args, target)
    evdir = None if args.no_evidence else out / "evidence"
    http = build_http(args, scope, Mode.ACTIVE, evdir)
    findings = Findings()
    decision = scope.decide(target, Mode.ACTIVE)
    if not decision.allowed:
        print(f"[!] authorization required for active testing: {decision.reason}",
              file=sys.stderr)
        return 2
    _run_active(target, http, findings, args)
    args._evidence = str(evdir) if evdir else None
    return _finish(args, target, findings, out,
                   coverage={"mode": "active (authorized)",
                             "modules": "endpoints, fingerprint, rag, agent, honeypot",
                             "requests": len(http.exchanges)},
                   not_tested=["authenticated-only surfaces",
                               "tool invocation (state-changing, out of recon scope)"])


def cmd_full(args) -> int:
    target = _norm(args.target)
    scope = load_scope(args)
    out = outdir(args, target)
    evdir = None if args.no_evidence else out / "evidence"
    http = build_http(args, scope, Mode.FULL, evdir)
    findings = Findings()
    decision = scope.decide(target, Mode.FULL)
    if not decision.allowed:
        print(f"[!] authorization required for a full assessment: {decision.reason}",
              file=sys.stderr)
        return 2
    _run_passive(target, http, findings)
    _run_active(target, http, findings, args)
    evasion.run(target, http, findings)
    args._evidence = str(evdir) if evdir else None
    return _finish(args, target, findings, out,
                   coverage={"mode": "full (authorized)",
                             "passive": "dns, tls, headers, jsrecon, wellknown, platform",
                             "active": "endpoints, fingerprint, rag, agent, honeypot",
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
    http = build_http(args, scope, Mode.PASSIVE,
                      out / "evidence" if not args.no_evidence else None)
    findings = Findings()
    evasion.run(target, http, findings, examples=args.query)
    args._evidence = None
    return _finish(args, target, findings, out,
                   coverage={"evasion rules modelled": "E01-E05, D02, D03"},
                   not_tested=["live detection confirmation (defender side)"])


def cmd_rules(args) -> int:
    queries = args.query or []
    if not queries:
        print("Modelled detection rules:")
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
        description="AI RECON - universal AI reconnaissance. Passive recon works "
                    "on any public AI platform; active/full testing requires an "
                    "explicit authorization scope. Developed by: AboBakr Mohamed",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  ai-recon passive https://chatgpt.com\n"
            "  ai-recon passive https://gemini.google.com\n"
            "  ai-recon active  https://target.com --scope authorized.txt\n"
            "  ai-recon full    https://target.com --scope authorized.txt\n"
            "  ai-recon scope   --allow 10.0.0.5 --authorized-by 'Jane (owner)' --save\n"
        ),
    )
    p.add_argument("--version", action="version",
                   version=f"AI RECON (ai-recon) {__version__} - "
                           f"Developed by: AboBakr Mohamed")

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--scope", metavar="FILE",
                        help="authorization scope file (required for active/full)")
    common.add_argument("--allow", action="append", metavar="HOST",
                        help="add an allow entry (repeatable)")
    common.add_argument("--allow-private", action="store_true",
                        help="permit private/loopback targets (own lab, active)")
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
                        help="chat endpoint path (active fingerprint)")
    common.add_argument("--field", default=None,
                        help="chat body field: messages|query|message")
    common.add_argument("--timeout", type=float, default=30.0)
    common.add_argument("-q", "--quiet", action="store_true")

    sub = p.add_subparsers(dest="command", required=True)

    sc = sub.add_parser("scope", help="manage the active-testing authorization scope")
    sc.add_argument("--allow", action="append", metavar="HOST")
    sc.add_argument("--allow-private", action="store_true")
    sc.add_argument("--deny", action="append", metavar="HOST")
    sc.add_argument("--note", metavar="TEXT")
    sc.add_argument("--authorized-by", metavar="NAME",
                    help="record who authorized this engagement")
    sc.add_argument("--save", action="store_true")
    sc.add_argument("--check", action="append", metavar="TARGET")
    sc.set_defaults(func=cmd_scope)

    for name, fn, help_ in (
            ("passive", cmd_passive, "passive recon (no scope; any public host)"),
            ("active", cmd_active, "active recon (authorized; needs --scope)"),
            ("full", cmd_full, "passive + active + evasion (authorized)"),
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
        print(f"[!] {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
