"""
matcher.py — the actual matching logic: does this Rule match this
Packet, and why (or why not)? Each sub-check returns both a bool and a
short, specific, human-readable explanation, so the dashboard can show
a real reason rather than a generic "no match".
"""
from __future__ import annotations
import ipaddress

from .models import Packet, Rule


def ip_matches(rule_source: str, packet_ip: str) -> tuple[bool, str]:
    rs = rule_source.strip()
    if rs.lower() == "any":
        return True, f"source {packet_ip} matches 'any'"
    try:
        if "/" in rs:
            network = ipaddress.ip_network(rs, strict=False)
            ok = ipaddress.ip_address(packet_ip) in network
            return ok, (f"source {packet_ip} is within {rs}" if ok
                        else f"source {packet_ip} is NOT within {rs}")
        else:
            ok = ipaddress.ip_address(packet_ip) == ipaddress.ip_address(rs)
            return ok, (f"source {packet_ip} equals {rs}" if ok
                        else f"source {packet_ip} does not equal {rs}")
    except ValueError:
        return False, f"rule source {rs!r} or packet source {packet_ip!r} is not a valid address"


def protocol_matches(rule_protocol: str, packet_protocol: str) -> tuple[bool, str]:
    rp = rule_protocol.strip().lower()
    pp = packet_protocol.strip().lower()
    if rp == "any":
        return True, f"protocol {pp} matches 'any'"
    ok = rp == pp
    return ok, (f"protocol {pp} matches {rp}" if ok else f"protocol {pp} does not match {rp}")


def port_matches(rule_port: str, packet_port: int, packet_protocol: str) -> tuple[bool, str]:
    if packet_protocol.strip().lower() == "icmp":
        return True, "port not applicable to ICMP"
    rp = rule_port.strip()
    if rp.lower() == "any":
        return True, f"port {packet_port} matches 'any'"
    if "-" in rp:
        start_s, end_s = rp.split("-", 1)
        try:
            start, end = int(start_s), int(end_s)
        except ValueError:
            return False, f"rule port range {rp!r} is invalid"
        ok = start <= packet_port <= end
        return ok, (f"port {packet_port} is within {start}-{end}" if ok
                    else f"port {packet_port} is outside {start}-{end}")
    try:
        rule_port_num = int(rp)
    except ValueError:
        return False, f"rule port {rp!r} is invalid"
    ok = rule_port_num == packet_port
    return ok, (f"port {packet_port} equals {rule_port_num}" if ok
                else f"port {packet_port} does not equal {rule_port_num}")


def rule_matches(rule: Rule, packet: Packet) -> tuple[bool, str]:
    """Returns (matched, reason). Does NOT check rule.enabled — callers
    (the engine) decide whether to evaluate disabled rules at all."""
    proto_ok, proto_reason = protocol_matches(rule.protocol, packet.protocol)
    ip_ok, ip_reason = ip_matches(rule.source_ip, packet.source_ip)
    port_ok, port_reason = port_matches(rule.dest_port, packet.dest_port, packet.protocol)

    if proto_ok and ip_ok and port_ok:
        return True, f"{proto_reason}; {ip_reason}; {port_reason}"

    failed = [r for ok, r in ((proto_ok, proto_reason), (ip_ok, ip_reason), (port_ok, port_reason)) if not ok]
    return False, "; ".join(failed)
