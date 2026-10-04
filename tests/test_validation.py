from firewall_sim.validation import (
    validate_source_ip, validate_dest_port, validate_protocol, validate_action,
    validate_priority, validate_rule_fields, validate_packet_fields,
)


# ---------------------------------------------------------------- source_ip

def test_valid_source_ip_any():
    assert validate_source_ip("any") is None


def test_valid_source_ip_host():
    assert validate_source_ip("10.1.2.3") is None


def test_valid_source_ip_cidr():
    assert validate_source_ip("10.0.0.0/8") is None


def test_invalid_source_ip():
    assert validate_source_ip("not-an-ip") is not None


def test_empty_source_ip_invalid():
    assert validate_source_ip("") is not None
    assert validate_source_ip("   ") is not None


# ---------------------------------------------------------------- dest_port

def test_valid_port_any():
    assert validate_dest_port("any") is None


def test_valid_port_single():
    assert validate_dest_port("443") is None


def test_valid_port_range():
    assert validate_dest_port("8000-8100") is None


def test_invalid_port_out_of_range():
    assert validate_dest_port("70000") is not None


def test_invalid_port_range_backwards():
    assert validate_dest_port("100-50") is not None


def test_invalid_port_not_a_number():
    assert validate_dest_port("abc") is not None


def test_invalid_port_range_malformed():
    assert validate_dest_port("100-") is not None


# ---------------------------------------------------------------- protocol / action / priority

def test_valid_protocols():
    for p in ("any", "tcp", "udp", "icmp"):
        assert validate_protocol(p) is None


def test_invalid_protocol():
    assert validate_protocol("ftp") is not None


def test_valid_actions():
    assert validate_action("allow") is None
    assert validate_action("deny") is None


def test_invalid_action():
    assert validate_action("maybe") is not None


def test_valid_priority():
    assert validate_priority(1) is None
    assert validate_priority("50") is None


def test_invalid_priority_zero_or_negative():
    assert validate_priority(0) is not None
    assert validate_priority(-5) is not None


def test_invalid_priority_not_a_number():
    assert validate_priority("high") is not None


# ---------------------------------------------------------------- validate_rule_fields

def test_validate_rule_fields_all_valid_returns_empty_dict():
    errors = validate_rule_fields(dict(
        name="test", action="allow", priority=10, source_ip="any", protocol="tcp", dest_port="80",
    ))
    assert errors == {}


def test_validate_rule_fields_reports_each_bad_field():
    errors = validate_rule_fields(dict(
        name="", action="bogus", priority=-1, source_ip="nope", protocol="ftp", dest_port="99999",
    ))
    assert set(errors.keys()) == {"name", "action", "priority", "source_ip", "protocol", "dest_port"}


# ---------------------------------------------------------------- validate_packet_fields

def test_validate_packet_fields_valid():
    errors = validate_packet_fields(dict(source_ip="10.1.1.1", dest_port="443", protocol="tcp"))
    assert errors == {}


def test_validate_packet_fields_rejects_any_ip():
    errors = validate_packet_fields(dict(source_ip="any", dest_port="443", protocol="tcp"))
    assert "source_ip" in errors


def test_validate_packet_fields_rejects_any_protocol():
    errors = validate_packet_fields(dict(source_ip="10.1.1.1", dest_port="443", protocol="any"))
    assert "protocol" in errors


def test_validate_packet_fields_rejects_bad_port():
    errors = validate_packet_fields(dict(source_ip="10.1.1.1", dest_port="not-a-port", protocol="tcp"))
    assert "dest_port" in errors


def test_validate_packet_fields_rejects_port_range():
    # A single simulated packet must have exactly one port, not a range.
    errors = validate_packet_fields(dict(source_ip="10.1.1.1", dest_port="80-90", protocol="tcp"))
    assert "dest_port" in errors
