"""
validation.py — validates the string fields a Rule is built from
(exactly what a person types into the dashboard's rule form). Every
function returns an error message string, or None if the value is
valid, so callers can build a {field: error} dict.
"""
from __future__ import annotations
import ipaddress

from .models import ACTIONS, PROTOCOLS


def validate_name(value: str):
    if not value or not value.strip():
        return "Name is required."
    if len(value) > 100:
        return "Name must be 100 characters or fewer."
    return None


def validate_action(value: str):
    if value not in ACTIONS:
        return f"Action must be one of: {', '.join(ACTIONS)}."
    return None


def validate_protocol(value: str):
    if value not in PROTOCOLS:
        return f"Protocol must be one of: {', '.join(PROTOCOLS)}."
    return None


def validate_priority(value) -> str | None:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "Priority must be a whole number."
    if n < 1:
        return "Priority must be 1 or greater (lower numbers are evaluated first)."
    return None


def validate_source_ip(value: str):
    if value is None:
        return "Source IP is required."
    v = value.strip()
    if not v:
        return "Source IP is required."
    if v.lower() == "any":
        return None
    try:
        if "/" in v:
            ipaddress.ip_network(v, strict=False)
        else:
            ipaddress.ip_address(v)
        return None
    except ValueError:
        return f"{value!r} is not a valid IP address, CIDR network (e.g. 10.0.0.0/8), or 'any'."


def validate_dest_port(value: str):
    if value is None:
        return "Destination port is required."
    v = value.strip()
    if not v:
        return "Destination port is required."
    if v.lower() == "any":
        return None
    if "-" in v:
        parts = v.split("-", 1)
        if len(parts) != 2 or not all(p.strip() for p in parts):
            return "Port range must look like 'start-end', e.g. 8000-8100."
        try:
            start, end = int(parts[0]), int(parts[1])
        except ValueError:
            return "Port range values must be whole numbers."
        if not (0 <= start <= 65535 and 0 <= end <= 65535):
            return "Ports must be between 0 and 65535."
        if start > end:
            return "Range start must be less than or equal to the end."
        return None
    try:
        p = int(v)
    except ValueError:
        return "Port must be a whole number, a range like '8000-8100', or 'any'."
    if not (0 <= p <= 65535):
        return "Port must be between 0 and 65535."
    return None


def validate_rule_fields(data: dict) -> dict:
    """data: {name, action, priority, source_ip, protocol, dest_port}.
    Returns {field: error_message} for every field that failed — empty
    dict means the rule is valid."""
    errors = {}
    checks = {
        "name": validate_name, "action": validate_action, "priority": validate_priority,
        "source_ip": validate_source_ip, "protocol": validate_protocol, "dest_port": validate_dest_port,
    }
    for field, check in checks.items():
        error = check(data.get(field))
        if error:
            errors[field] = error
    return errors


def validate_packet_fields(data: dict) -> dict:
    """data: {source_ip, dest_port, protocol} for a piece of simulated
    traffic. dest_port here must be a single concrete port (not 'any'
    or a range — a real packet has exactly one destination port)."""
    errors = {}

    ip_error = validate_source_ip(data.get("source_ip"))
    if ip_error or (data.get("source_ip") or "").strip().lower() == "any":
        errors["source_ip"] = ip_error or "Simulated traffic must have a specific source IP, not 'any'."

    proto_error = validate_protocol(data.get("protocol"))
    if proto_error or data.get("protocol") == "any":
        errors["protocol"] = proto_error or "Simulated traffic must have a specific protocol, not 'any'."

    port_value = data.get("dest_port")
    try:
        port = int(port_value)
        if not (0 <= port <= 65535):
            errors["dest_port"] = "Port must be between 0 and 65535."
    except (TypeError, ValueError):
        errors["dest_port"] = "Destination port must be a whole number (a real packet has exactly one port)."

    return errors
