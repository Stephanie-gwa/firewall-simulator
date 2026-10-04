import pytest

from firewall_sim.models import Packet, Rule, EvaluationResult
from firewall_sim.store import Store


@pytest.fixture
def store():
    return Store(":memory:")


def make_rule(**kw):
    defaults = dict(
        id=None, name="r", action="allow", priority=10,
        source_ip="any", protocol="any", dest_port="any", enabled=True, description="",
    )
    defaults.update(kw)
    return Rule(**defaults)


# ---------------------------------------------------------------- rule CRUD

def test_add_and_get_rule(store):
    rid = store.add_rule(make_rule(name="my rule"))
    rule = store.get_rule(rid)
    assert rule.name == "my rule"
    assert rule.id == rid


def test_get_nonexistent_rule_returns_none(store):
    assert store.get_rule(9999) is None


def test_list_rules_sorted_by_priority_then_id(store):
    store.add_rule(make_rule(name="c", priority=30))
    store.add_rule(make_rule(name="a", priority=10))
    store.add_rule(make_rule(name="b", priority=10))
    names = [r.name for r in store.list_rules()]
    assert names == ["a", "b", "c"]


def test_update_rule(store):
    rid = store.add_rule(make_rule(name="original"))
    store.update_rule(rid, name="renamed", priority=99)
    rule = store.get_rule(rid)
    assert rule.name == "renamed"
    assert rule.priority == 99


def test_delete_rule(store):
    rid = store.add_rule(make_rule())
    store.delete_rule(rid)
    assert store.get_rule(rid) is None


def test_set_rule_enabled(store):
    rid = store.add_rule(make_rule(enabled=True))
    store.set_rule_enabled(rid, False)
    assert store.get_rule(rid).enabled is False
    store.set_rule_enabled(rid, True)
    assert store.get_rule(rid).enabled is True


def test_list_rules_enabled_only(store):
    store.add_rule(make_rule(name="on", enabled=True))
    store.add_rule(make_rule(name="off", enabled=False))
    names = [r.name for r in store.list_rules(enabled_only=True)]
    assert names == ["on"]


# ---------------------------------------------------------------- settings

def test_default_policy_starts_as_deny(store):
    assert store.get_default_policy() == "deny"


def test_set_default_policy(store):
    store.set_default_policy("allow")
    assert store.get_default_policy() == "allow"
    store.set_default_policy("deny")
    assert store.get_default_policy() == "deny"


# ---------------------------------------------------------------- event log

def test_log_event_and_list(store):
    packet = Packet(source_ip="1.2.3.4", dest_port=80, protocol="tcp", description="test")
    rule = make_rule(id=1, name="matched")
    result = EvaluationResult(action="allow", matched_rule=rule, used_default=False, trace=[])
    store.log_event(packet, result)
    events = store.list_events()
    assert len(events) == 1
    assert events[0]["source_ip"] == "1.2.3.4"
    assert events[0]["matched_rule_name"] == "matched"


def test_list_events_most_recent_first(store):
    for i in range(3):
        packet = Packet(source_ip=f"1.2.3.{i}", dest_port=80, protocol="tcp")
        result = EvaluationResult(action="allow", matched_rule=None, used_default=True, trace=[])
        store.log_event(packet, result)
    events = store.list_events()
    assert [e["source_ip"] for e in events] == ["1.2.3.2", "1.2.3.1", "1.2.3.0"]


def test_list_events_respects_limit(store):
    for i in range(5):
        packet = Packet(source_ip="1.2.3.4", dest_port=80, protocol="tcp")
        result = EvaluationResult(action="allow", matched_rule=None, used_default=True, trace=[])
        store.log_event(packet, result)
    assert len(store.list_events(limit=2)) == 2


def test_clear_events(store):
    packet = Packet(source_ip="1.2.3.4", dest_port=80, protocol="tcp")
    result = EvaluationResult(action="allow", matched_rule=None, used_default=True, trace=[])
    store.log_event(packet, result)
    store.clear_events()
    assert store.list_events() == []


def test_event_counts(store):
    for action in ("allow", "allow", "deny"):
        packet = Packet(source_ip="1.2.3.4", dest_port=80, protocol="tcp")
        result = EvaluationResult(action=action, matched_rule=None, used_default=True, trace=[])
        store.log_event(packet, result)
    counts = store.event_counts()
    assert counts == {"allow": 2, "deny": 1}


# ---------------------------------------------------------------- seeding

def test_seed_if_empty_populates(store):
    from firewall_sim.sample_data import DEFAULT_RULES
    store.seed_if_empty(DEFAULT_RULES)
    assert len(store.list_rules()) == len(DEFAULT_RULES)


def test_seed_if_empty_does_not_duplicate(store):
    from firewall_sim.sample_data import DEFAULT_RULES
    store.seed_if_empty(DEFAULT_RULES)
    store.seed_if_empty(DEFAULT_RULES)
    assert len(store.list_rules()) == len(DEFAULT_RULES)
