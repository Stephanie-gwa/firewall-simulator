import pytest

from firewall_sim.engine import FirewallEngine
from firewall_sim.models import Packet, Rule
from firewall_sim.store import Store


@pytest.fixture
def store():
    return Store(":memory:")


@pytest.fixture
def engine(store):
    return FirewallEngine(store)


def add(store, **kw):
    defaults = dict(
        id=None, name="rule", action="allow", priority=100,
        source_ip="any", protocol="any", dest_port="any", enabled=True, description="",
    )
    defaults.update(kw)
    return store.add_rule(Rule(**defaults))


def pkt(**kw):
    defaults = dict(source_ip="1.2.3.4", dest_port=80, protocol="tcp", description="")
    defaults.update(kw)
    return Packet(**defaults)


# ---------------------------------------------------------------- default policy fallback

def test_no_rules_uses_default_policy_deny(engine, store):
    store.set_default_policy("deny")
    result = engine.evaluate(pkt(), log=False)
    assert result.action == "deny"
    assert result.used_default is True
    assert result.matched_rule is None


def test_no_rules_uses_default_policy_allow(engine, store):
    store.set_default_policy("allow")
    result = engine.evaluate(pkt(), log=False)
    assert result.action == "allow"
    assert result.used_default is True


def test_no_matching_rule_falls_through_to_default(engine, store):
    add(store, name="only https", action="allow", priority=10, protocol="tcp", dest_port="443")
    store.set_default_policy("deny")
    result = engine.evaluate(pkt(dest_port=22), log=False)
    assert result.action == "deny"
    assert result.used_default is True


# ---------------------------------------------------------------- first match wins / priority order

def test_lower_priority_number_wins_when_both_match(engine, store):
    add(store, name="deny all", action="deny", priority=50, source_ip="any", protocol="any", dest_port="any")
    add(store, name="allow ssh", action="allow", priority=10, source_ip="any", protocol="tcp", dest_port="22")
    result = engine.evaluate(pkt(dest_port=22, protocol="tcp"), log=False)
    assert result.action == "allow"
    assert result.matched_rule.name == "allow ssh"


def test_higher_priority_number_evaluated_later_does_not_override(engine, store):
    add(store, name="allow ssh", action="allow", priority=10, source_ip="any", protocol="tcp", dest_port="22")
    add(store, name="deny all", action="deny", priority=50, source_ip="any", protocol="any", dest_port="any")
    result = engine.evaluate(pkt(dest_port=22, protocol="tcp"), log=False)
    assert result.action == "allow"
    assert result.matched_rule.name == "allow ssh"


def test_priority_order_is_independent_of_insertion_order(engine, store):
    # Insert the higher-priority-number (lower precedence) rule FIRST.
    add(store, name="deny all", action="deny", priority=99, source_ip="any", protocol="any", dest_port="any")
    add(store, name="allow http", action="allow", priority=1, source_ip="any", protocol="tcp", dest_port="80")
    result = engine.evaluate(pkt(dest_port=80, protocol="tcp"), log=False)
    assert result.matched_rule.name == "allow http"


def test_ties_broken_by_rule_id_ascending(engine, store):
    id_a = add(store, name="rule A", action="deny", priority=10, source_ip="any", protocol="any", dest_port="any")
    id_b = add(store, name="rule B", action="allow", priority=10, source_ip="any", protocol="any", dest_port="any")
    assert id_a < id_b
    result = engine.evaluate(pkt(), log=False)
    assert result.matched_rule.name == "rule A"  # created first, same priority


def test_more_specific_rule_loses_to_broader_rule_with_lower_priority_number(engine, store):
    """This is the classic 'priority footgun' the README should call out:
    a broad allow at priority 10 shadows a more specific rule at
    priority 30, even though the specific rule also matches."""
    add(store, name="allow internal LAN", action="allow", priority=10,
        source_ip="10.0.0.0/8", protocol="any", dest_port="any")
    add(store, name="allow dns", action="allow", priority=30,
        source_ip="any", protocol="udp", dest_port="53")
    result = engine.evaluate(pkt(source_ip="10.0.0.1", dest_port=53, protocol="udp"), log=False)
    assert result.matched_rule.name == "allow internal LAN"


# ---------------------------------------------------------------- disabled rules

def test_disabled_rule_is_never_matched(engine, store):
    add(store, name="disabled allow", action="allow", priority=1,
        source_ip="any", protocol="tcp", dest_port="22", enabled=False)
    store.set_default_policy("deny")
    result = engine.evaluate(pkt(dest_port=22, protocol="tcp"), log=False)
    assert result.action == "deny"
    assert result.used_default is True


def test_disabled_rule_appears_in_trace_as_skipped(engine, store):
    add(store, name="disabled rule", action="allow", priority=1,
        source_ip="any", protocol="any", dest_port="any", enabled=False)
    result = engine.evaluate(pkt(), log=False)
    assert len(result.trace) == 1
    assert result.trace[0].matched is False
    assert "disabled" in result.trace[0].reason


def test_re_enabling_a_rule_makes_it_effective_again(engine, store):
    rule_id = add(store, name="ssh rule", action="allow", priority=1,
                  source_ip="any", protocol="tcp", dest_port="22", enabled=False)
    store.set_default_policy("deny")
    assert engine.evaluate(pkt(dest_port=22, protocol="tcp"), log=False).action == "deny"

    store.set_rule_enabled(rule_id, True)
    assert engine.evaluate(pkt(dest_port=22, protocol="tcp"), log=False).action == "allow"


# ---------------------------------------------------------------- trace / explanation

def test_trace_stops_at_first_match(engine, store):
    add(store, name="first", action="allow", priority=1, source_ip="any", protocol="any", dest_port="any")
    add(store, name="second", action="deny", priority=2, source_ip="any", protocol="any", dest_port="any")
    result = engine.evaluate(pkt(), log=False)
    assert len(result.trace) == 1
    assert result.trace[0].rule.name == "first"


def test_trace_includes_all_considered_rules_when_none_match():
    store = Store(":memory:")
    engine = FirewallEngine(store)
    add(store, name="https only", action="allow", priority=1, source_ip="any", protocol="tcp", dest_port="443")
    add(store, name="ssh only", action="allow", priority=2, source_ip="any", protocol="tcp", dest_port="22")
    result = engine.evaluate(pkt(dest_port=8080, protocol="tcp"), log=False)
    assert len(result.trace) == 2
    assert all(t.matched is False for t in result.trace)


def test_reason_summary_names_matched_rule(engine, store):
    add(store, name="my special rule", action="deny", priority=1, source_ip="any", protocol="any", dest_port="any")
    result = engine.evaluate(pkt(), log=False)
    assert "my special rule" in result.reason_summary


def test_reason_summary_for_default_policy():
    store = Store(":memory:")
    engine = FirewallEngine(store)
    result = engine.evaluate(pkt(), log=False)
    assert "default policy" in result.reason_summary.lower()


# ---------------------------------------------------------------- logging

def test_evaluate_logs_event_by_default(engine, store):
    add(store, name="allow all", action="allow", priority=1, source_ip="any", protocol="any", dest_port="any")
    engine.evaluate(pkt())
    events = store.list_events()
    assert len(events) == 1
    assert events[0]["action"] == "allow"
    assert events[0]["matched_rule_name"] == "allow all"


def test_evaluate_can_skip_logging(engine, store):
    add(store, name="allow all", action="allow", priority=1, source_ip="any", protocol="any", dest_port="any")
    engine.evaluate(pkt(), log=False)
    assert store.list_events() == []


def test_logged_event_records_default_policy_use(engine, store):
    store.set_default_policy("deny")
    engine.evaluate(pkt())
    events = store.list_events()
    assert events[0]["used_default"] == 1
    assert events[0]["matched_rule_id"] is None


# ---------------------------------------------------------------- realistic scenario (sample data)

def test_sample_rule_set_matches_expected_outcomes():
    from firewall_sim.sample_data import DEFAULT_RULES, SAMPLE_TRAFFIC

    store = Store(":memory:")
    store.seed_if_empty(DEFAULT_RULES)
    store.set_default_policy("deny")
    engine = FirewallEngine(store)

    by_name = {t["name"]: t for t in SAMPLE_TRAFFIC}

    def run(name):
        t = by_name[name]
        return engine.evaluate(
            Packet(source_ip=t["source_ip"], dest_port=t["dest_port"], protocol=t["protocol"]),
            log=False,
        )

    r = run("Internal SSH session")
    assert r.action == "allow" and r.matched_rule.name == "Allow internal LAN"

    r = run("Office HTTPS request")
    assert r.action == "allow" and r.matched_rule.name == "Allow HTTPS"

    r = run("DNS query from internal resolver")
    assert r.action == "allow" and r.matched_rule.name == "Allow internal LAN"  # not "Allow DNS" — priority!

    r = run("Suspicious port probe")
    assert r.action == "deny" and r.matched_rule.name == "Block known-bad host"

    r = run("Ping sweep from known-bad host")
    assert r.action == "deny" and r.matched_rule.name == "Block known-bad host"

    r = run("External RDP attempt")
    assert r.action == "deny" and r.matched_rule.name == "Block RDP from the internet"

    r = run("Unclassified external traffic")
    assert r.action == "deny" and r.used_default is True
