"""
models.py — the data model. A Rule describes one line of firewall
policy; a Packet describes one piece of simulated traffic; an
EvaluationResult is what you get back after running a Packet through
the engine, including a full TraceEntry per rule considered so the
dashboard can show exactly why each rule did or didn't match.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Optional

ACTIONS = ("allow", "deny")
PROTOCOLS = ("any", "tcp", "udp", "icmp")


@dataclass
class Rule:
    id: Optional[int]
    name: str
    action: str            # "allow" | "deny"
    priority: int            # lower number = evaluated first (higher precedence)
    source_ip: str             # "any", a single IP, or CIDR e.g. "10.0.0.0/8"
    protocol: str                # "any" | "tcp" | "udp" | "icmp"
    dest_port: str                 # "any", a single port, or a range "8000-8100"
    enabled: bool = True
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "id": self.id, "name": self.name, "action": self.action,
            "priority": self.priority, "source_ip": self.source_ip,
            "protocol": self.protocol, "dest_port": self.dest_port,
            "enabled": self.enabled, "description": self.description,
        }


@dataclass
class Packet:
    source_ip: str
    dest_port: int
    protocol: str           # "tcp" | "udp" | "icmp"
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "source_ip": self.source_ip, "dest_port": self.dest_port,
            "protocol": self.protocol, "description": self.description,
        }


@dataclass
class TraceEntry:
    rule: Rule
    matched: bool
    reason: str

    def to_dict(self) -> dict:
        return {"rule": self.rule.to_dict(), "matched": self.matched, "reason": self.reason}


@dataclass
class EvaluationResult:
    action: str                          # "allow" | "deny" — the final decision
    matched_rule: Optional[Rule]           # None if the default policy was used
    used_default: bool
    trace: list = field(default_factory=list)   # list[TraceEntry], in evaluation order
    packet: Optional[Packet] = None
    timestamp: Optional[str] = None

    @property
    def reason_summary(self) -> str:
        if self.matched_rule is not None:
            return f"Matched rule #{self.matched_rule.id} ({self.matched_rule.name!r})"
        return "No enabled rule matched — fell through to the default policy"

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "matched_rule": self.matched_rule.to_dict() if self.matched_rule else None,
            "used_default": self.used_default,
            "reason_summary": self.reason_summary,
            "trace": [t.to_dict() for t in self.trace],
            "packet": self.packet.to_dict() if self.packet else None,
            "timestamp": self.timestamp,
        }
