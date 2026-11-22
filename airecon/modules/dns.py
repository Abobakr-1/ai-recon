"""dns.py — passive DNS facts about a host (no target interaction).

Collects publicly resolvable records: A/AAAA (via the OS resolver) and, when a
public resolver is reachable over UDP/53, CNAME / NS / MX / TXT. Results are
recorded as observations. If a record type cannot be retrieved (no egress to a
resolver, timeout), that is reported honestly as "unavailable", never guessed.
"""

from __future__ import annotations

import random
import socket
import struct
from dataclasses import dataclass

from ..core.findings import Confidence, Findings

MODULE = "passive/dns"

PUBLIC_RESOLVERS = [("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53)]

QTYPES = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


# --------------------------------------------------------------------------- #
# minimal DNS client (stdlib only)
# --------------------------------------------------------------------------- #
def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.rstrip(".").split("."):
        if not label:
            continue
        out += bytes([len(label)]) + label.encode("ascii", "ignore")
    return out + b"\x00"


def _skip_name(data: bytes, offset: int) -> int:
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:  # pointer
            return offset + 2
        offset += 1 + length
    return offset


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels = []
    jumped = False
    end = offset
    hops = 0
    while offset < len(data) and hops < 50:
        hops += 1
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            offset = ptr
            jumped = True
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), (end if jumped else offset)


@dataclass
class DnsResult:
    records: dict[str, list[str]]
    resolver: str | None
    error: str | None = None


def query(name: str, qtype: str, resolver: tuple[str, int], timeout: float = 4.0) -> list[str]:
    tid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack(">HH", QTYPES[qtype], 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, resolver)
        data, _ = sock.recvfrom(4096)
    finally:
        sock.close()

    if len(data) < 12:
        return []
    _, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
    if flags & 0x000F:  # RCODE != 0
        return []
    offset = 12
    for _ in range(qd):
        offset = _skip_name(data, offset) + 4
    answers: list[str] = []
    for _ in range(an):
        offset = _skip_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        offset += rdlen
        if rtype == 1 and len(rdata) == 4:
            answers.append(".".join(str(b) for b in rdata))
        elif rtype == 28 and len(rdata) == 16:
            answers.append(":".join(f"{rdata[i]:02x}{rdata[i+1]:02x}" for i in range(0, 16, 2)))
        elif rtype in (2, 5):
            val, _ = _read_name(data, offset - rdlen)
            answers.append(val)
        elif rtype == 15:
            pref = struct.unpack(">H", rdata[:2])[0] if len(rdata) >= 2 else 0
            val, _ = _read_name(data, offset - rdlen + 2)
            answers.append(f"{pref} {val}")
        elif rtype == 16:
            parts = []
            i = 0
            while i < len(rdata):
                ln = rdata[i]
                parts.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            answers.append("".join(parts))
    return answers


def resolve_all(name: str) -> DnsResult:
    records: dict[str, list[str]] = {}
    # A/AAAA via OS resolver — always attempt
    for fam, label in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            infos = socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)
            ips = sorted({i[4][0] for i in infos})
            if ips:
                records[label] = ips
        except socket.gaierror:
            pass

    # CNAME/NS/MX/TXT need a reachable resolver on UDP/53
    resolver = None
    for candidate in PUBLIC_RESOLVERS:
        try:
            test = query(name, "A", candidate, timeout=3.0)
            resolver = candidate
            if test and "A" not in records:
                records["A"] = test
            break
        except (OSError, socket.timeout):
            continue

    error = None
    if resolver is None:
        error = "no public resolver reachable on UDP/53 (A/AAAA only, from OS resolver)"
    else:
        for qt in ("CNAME", "NS", "MX", "TXT"):
            try:
                vals = query(name, qt, resolver, timeout=4.0)
                if vals:
                    records[qt] = vals
            except (OSError, socket.timeout, struct.error):
                continue
    return DnsResult(records=records, resolver=f"{resolver[0]}:{resolver[1]}" if resolver else None,
                     error=error)


def run(target: str, http, findings: Findings) -> dict:
    from urllib.parse import urlparse
    host = urlparse(target if "://" in target else "http://" + target).hostname
    if not host:
        findings.add_simple(MODULE, "No hostname to resolve",
                            f"Could not parse a hostname from {target}.", Confidence.INFO)
        return {"records": {}}

    res = resolve_all(host)
    if res.records:
        detail = "; ".join(f"{k}={', '.join(v[:4])}" for k, v in res.records.items())
        findings.add_simple(
            MODULE, f"DNS records for {host}",
            detail, Confidence.CONFIRMED, data={"host": host, "records": res.records},
            tags=["dns"],
        )
        # CNAME chain reveals hosting/hygiene
        if "CNAME" in res.records:
            findings.add_simple(
                MODULE, "CNAME chain observed",
                " -> ".join(res.records["CNAME"]),
                Confidence.LIKELY, data={"cname": res.records["CNAME"]}, tags=["dns", "cname"],
            )
        if "TXT" in res.records:
            spf = [t for t in res.records["TXT"] if "v=spf" in t.lower() or "verify" in t.lower()]
            if spf:
                findings.add_simple(
                    MODULE, "TXT records (SPF/verification)",
                    "; ".join(spf[:3]), Confidence.INFO, tags=["dns", "txt"],
                )
    else:
        findings.add_simple(
            MODULE, f"No DNS records resolved for {host}",
            res.error or "resolution returned no records.",
            Confidence.INFO, data={"host": host, "error": res.error},
        )
    return {"records": res.records, "resolver": res.resolver, "error": res.error}
