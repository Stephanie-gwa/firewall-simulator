from firewall_sim.matcher import ip_matches, port_matches, protocol_matches, rule_matches
from firewall_sim.models import Packet, Rule


def make_rule(**kw):
    defaults = dict(
        id=1, name="test rule", action="allow", priority=10,
        source_ip="any", protocol="any", dest_port="any", enabled=True,
    )
    defaults.update(kw)
    return Rule(**defaults)


def make_packet(**kw):
    defaults = dict(source_ip="1.2.3.4", dest_port=80, protocol="tcp")
    defaults.update(kw)
    return Packet(**defaults)


# ---------------------------------------------------------------- ip_matches

def test_ip_matches_any():
    ok, reason = ip_matches("any", "10.1.2.3")
    assert ok is True
    assert "any" in reason


def test_ip_matches_exact_match():
    ok, _ = ip_matches("10.1.2.3", "10.1.2.3")
    assert ok is True


def test_ip_matches_exact_mismatch():
    ok, reason = ip_matches("10.1.2.3", "10.1.2.4")
    assert ok is False
    assert "does not equal" in reason


def test_ip_matches_cidr_inside():
    ok, _ = ip_matches("10.0.0.0/8", "10.5.6.7")
    assert ok is True


def test_ip_matches_cidr_outside():
    ok, reason = ip_matches("10.0.0.0/8", "192.168.1.1")
    assert ok is False
    assert "NOT within" in reason


def test_ip_matches_cidr_boundary():
    assert ip_matches("192.168.1.0/24", "192.168.1.255")[0] is True
    assert ip_matches("192.168.1.0/24", "192.168.2.0")[0] is False


def test_ip_matches_single_host_cidr():
    assert ip_matches("10.1.1.1/32", "10.1.1.1")[0] is True
    assert ip_matches("10.1.1.1/32", "10.1.1.2")[0] is False


def test_ip_matches_invalid_rule_ip_does_not_crash():
    ok, reason = ip_matches("not-an-ip", "10.1.1.1")
    assert ok is False
    assert "not a valid address" in reason


# ---------------------------------------------------------------- protocol_matches

def test_protocol_matches_any():
    assert protocol_matches("any", "tcp")[0] is True
    assert protocol_matches("any", "icmp")[0] is True


def test_protocol_matches_exact():
    assert protocol_matches("tcp", "tcp")[0] is True
    assert protocol_matches("tcp", "udp")[0] is False


def test_protocol_matches_case_insensitive():
    assert protocol_matches("TCP", "tcp")[0] is True


# ---------------------------------------------------------------- port_matches

def test_port_matches_any():
    assert port_matches("any", 443, "tcp")[0] is True


def test_port_matches_exact():
    assert port_matches("443", 443, "tcp")[0] is True
    assert port_matches("443", 80, "tcp")[0] is False


def test_port_matches_range_inside():
    assert port_matches("8000-8100", 8050, "tcp")[0] is True


def test_port_matches_range_boundaries_inclusive():
    assert port_matches("8000-8100", 8000, "tcp")[0] is True
    assert port_matches("8000-8100", 8100, "tcp")[0] is True


def test_port_matches_range_outside():
    assert port_matches("8000-8100", 7999, "tcp")[0] is False
    assert port_matches("8000-8100", 8101, "tcp")[0] is False


def test_port_matches_icmp_ignores_port_value():
    # A rule with a specific port still "matches" ICMP traffic on the
    # port dimension, because ICMP has no port concept.
    ok, reason = port_matches("443", 0, "icmp")
    assert ok is True
    assert "not applicable" in reason


# ---------------------------------------------------------------- rule_matches (combined)

def test_rule_matches_all_any_matches_everything():
    rule = make_rule(source_ip="any", protocol="any", dest_port="any")
    ok, _ = rule_matches(rule, make_packet(source_ip="203.0.113.5", dest_port=9999, protocol="udp"))
    assert ok is True


def test_rule_matches_requires_all_three_dimensions():
    rule = make_rule(source_ip="10.0.0.0/8", protocol="tcp", dest_port="443")
    # right network, wrong protocol
    ok, reason = rule_matches(rule, make_packet(source_ip="10.1.1.1", dest_port=443, protocol="udp"))
    assert ok is False
    assert "protocol" in reason


def test_rule_matches_full_match():
    rule = make_rule(source_ip="10.0.0.0/8", protocol="tcp", dest_port="22")
    ok, reason = rule_matches(rule, make_packet(source_ip="10.5.5.5", dest_port=22, protocol="tcp"))
    assert ok is True
    assert "10.5.5.5" in reason and "22" in reason


def test_rule_matches_reason_lists_all_failed_dimensions():
    rule = make_rule(source_ip="192.168.1.0/24", protocol="udp", dest_port="53")
    ok, reason = rule_matches(rule, make_packet(source_ip="10.1.1.1", dest_port=443, protocol="tcp"))
    assert ok is False
    assert "protocol" in reason and "source" in reason and "port" in reason
