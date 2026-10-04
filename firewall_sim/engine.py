"""
engine.py — the evaluation engine: given a Packet and the current set
of rules, decide allow or deny.

Algorithm (first-match-wins, like iptables/most real firewalls):
  1. Take all rules, sorted by priority ascending (lower number first),
     ties broken by rule id ascending (so creation order is stable).
  2. Walk the list in order. Disabled rules are skipped (recorded in
     the trace as skipped, but never evaluated for a match).
  3. The first ENABLED rule whose source IP, protocol, and destination
     port all match the packet decides the outcome. Evaluation stops
     there — later rules are never considered.
  4. If no rule matches, the engine's default policy applies.

This is a pure simulation: nothing here calls out to iptables, pf,
Windows Firewall, or any other real network-filtering mechanism.
"""
from __future__ import annotations

from .matcher import rule_matches
from .models import EvaluationResult, Packet, TraceEntry
from .store import Store


class FirewallEngine:
    def __init__(self, store: Store):
        self.store = store

    def evaluate(self, packet: Packet, log: bool = True) -> EvaluationResult:
        rules = self.store.list_rules(enabled_only=False)
        trace = []

        for rule in rules:
            if not rule.enabled:
                trace.append(TraceEntry(rule=rule, matched=False, reason="rule is disabled — skipped"))
                continue
            matched, reason = rule_matches(rule, packet)
            trace.append(TraceEntry(rule=rule, matched=matched, reason=reason))
            if matched:
                result = EvaluationResult(
                    action=rule.action, matched_rule=rule, used_default=False,
                    trace=trace, packet=packet,
                )
                if log:
                    self.store.log_event(packet, result)
                return result

        default_policy = self.store.get_default_policy()
        result = EvaluationResult(
            action=default_policy, matched_rule=None, used_default=True,
            trace=trace, packet=packet,
        )
        if log:
            self.store.log_event(packet, result)
        return result
