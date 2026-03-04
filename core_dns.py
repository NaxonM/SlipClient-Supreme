"""DNS scanning primitives extracted from core.py."""

from __future__ import annotations

import random
import re
import socket
import struct


def _dns_build_query(domain: str, qtype: int) -> tuple[int, bytes]:
    txid = random.randint(1, 65534)
    labels = domain.encode().split(b".")
    qname = b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"
    pkt = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack(">HH", qtype, 0x0001)
    return txid, pkt


def dns_udp_query(ip: str, domain: str, qtype: int, timeout: float = 2.0):
    """Returns (ok, rcode, response-bytes). ok=True for NOERROR or NXDOMAIN."""
    try:
        txid, pkt = _dns_build_query(domain, qtype)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(pkt, (ip, 53))
        resp, _ = s.recvfrom(2048)
        s.close()
        if len(resp) < 4:
            return False, -1, b""
        rx = struct.unpack(">H", resp[:2])[0]
        if rx != txid:
            return False, -1, b""
        rcode = struct.unpack(">H", resp[2:4])[0] & 0xF
        return rcode in (0, 3), rcode, resp
    except Exception:
        return False, -1, b""


def _dns_parent_domain(domain: str) -> str:
    labels = [p for p in domain.split(".") if p]
    return ".".join(labels[1:]) if len(labels) > 2 else domain


def _dns_read_name(msg: bytes, pos: int) -> tuple[str, int]:
    labels = []
    jumped = False
    jump_end = pos
    loops = 0
    while pos < len(msg) and loops < 64:
        loops += 1
        ln = msg[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0 == 0xC0:
            if pos + 1 >= len(msg):
                break
            ptr = ((ln & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                jump_end = pos + 2
            pos = ptr
            jumped = True
            continue
        pos += 1
        if pos + ln > len(msg):
            break
        labels.append(msg[pos:pos + ln].decode("utf-8", errors="ignore"))
        pos += ln
    return ".".join(labels), (jump_end if jumped else pos)


def _dns_extract_a_records(resp: bytes) -> list[str]:
    if len(resp) < 12:
        return []
    qd = struct.unpack(">H", resp[4:6])[0]
    an = struct.unpack(">H", resp[6:8])[0]
    pos = 12
    for _ in range(qd):
        _, pos = _dns_read_name(resp, pos)
        pos += 4
    out = []
    for _ in range(an):
        if pos + 10 > len(resp):
            break
        _, pos = _dns_read_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype = struct.unpack(">H", resp[pos:pos + 2])[0]
        pos += 2
        pos += 2
        pos += 4
        rdlen = struct.unpack(">H", resp[pos:pos + 2])[0]
        pos += 2
        if pos + rdlen > len(resp):
            break
        rdata = resp[pos:pos + rdlen]
        if rtype == 1 and rdlen == 4:
            out.append(socket.inet_ntoa(rdata))
        pos += rdlen
    return out


def _dns_parse_ns_hosts(resp: bytes) -> list[str]:
    if len(resp) < 12:
        return []
    qd = struct.unpack(">H", resp[4:6])[0]
    an = struct.unpack(">H", resp[6:8])[0]
    ns = struct.unpack(">H", resp[8:10])[0]
    pos = 12
    for _ in range(qd):
        _, pos = _dns_read_name(resp, pos)
        pos += 4
    out = []
    for _ in range(an + ns):
        if pos + 10 > len(resp):
            break
        _, pos = _dns_read_name(resp, pos)
        if pos + 10 > len(resp):
            break
        rtype = struct.unpack(">H", resp[pos:pos + 2])[0]
        pos += 8
        rdlen = struct.unpack(">H", resp[pos:pos + 2])[0]
        pos += 2
        if pos + rdlen > len(resp):
            break
        if rtype == 2:
            name, _ = _dns_read_name(resp, pos)
            if name:
                out.append(name.rstrip("."))
        pos += rdlen
    return out


def scan_resolver_dns_tunnel(
    ip: str,
    domain: str,
    timeout: float = 2.0,
    mode: str = "quick",
) -> tuple[bool, dict]:
    """
    SlipNet-style compatibility checks.
    mode=quick  -> basic + one nested + hijack check (faster)
    mode=full   -> adds NS/TXT/second nested checks (more thorough)
    """
    parent = _dns_parent_domain(domain)
    rand = lambda n=8: "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

    basic_ok, _, _ = dns_udp_query(ip, f"{rand()}.{parent}", 1, timeout)
    if not basic_ok:
        return False, {"basic": False, "ns": False, "txt": False, "r1": False, "r2": False, "hijack": False}

    r1_ok, _, _ = dns_udp_query(ip, f"{rand()}.{rand()}.{domain}", 1, timeout)

    ns_ok = False
    txt_ok = False
    r2_ok = False
    if mode == "full":
        ok_ns, _, ns_resp = dns_udp_query(ip, parent, 2, timeout)
        if ok_ns:
            hosts = _dns_parse_ns_hosts(ns_resp)
            if hosts:
                glue_ok, _, _ = dns_udp_query(ip, hosts[0], 1, timeout)
                ns_ok = glue_ok
        txt_ok, _, _ = dns_udp_query(ip, f"{rand()}.{parent}", 16, timeout)
        r2_ok, _, _ = dns_udp_query(ip, f"{rand()}.{rand()}.{domain}", 1, timeout)

    hijack = False
    cf_ok, _, cf_resp = dns_udp_query(ip, "one.one.one.one", 1, timeout)
    if cf_ok and cf_resp:
        for a in _dns_extract_a_records(cf_resp):
            if re.match(r"^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.)", a):
                hijack = True
                break

    checks = {"basic": True, "ns": ns_ok, "txt": txt_ok, "r1": r1_ok, "r2": r2_ok, "hijack": hijack}
    min_ok = basic_ok and r1_ok
    return (min_ok and not hijack), checks


def burst_dns_success(ip: str, domain: str, timeout: float, count: int = 10) -> float:
    """Return success ratio for repeated randomized DNS tunnel queries."""
    if count <= 0:
        return 1.0
    ok = 0
    for _ in range(count):
        q = f"{''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(8))}.{domain}"
        passed, _, _ = dns_udp_query(ip, q, 1, timeout)
        if passed:
            ok += 1
    return ok / float(count)
