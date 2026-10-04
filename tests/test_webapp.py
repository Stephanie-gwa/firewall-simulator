import json


def test_dashboard_loads_and_shows_seeded_rules(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"Allow internal LAN" in resp.data
    assert b"Simulation only" in resp.data


def test_dashboard_shows_default_policy(client):
    resp = client.get("/")
    assert b"deny" in resp.data


# ---------------------------------------------------------------- rule CRUD via HTTP

def test_new_rule_form_renders(client):
    resp = client.get("/rules/new")
    assert resp.status_code == 200
    assert b"New rule" in resp.data


def test_create_rule_via_post(client, store):
    resp = client.post("/rules/new", data={
        "name": "Test rule", "action": "deny", "priority": "5",
        "source_ip": "192.168.1.0/24", "protocol": "tcp", "dest_port": "23",
        "enabled": "on", "description": "block telnet",
    }, follow_redirects=True)
    assert resp.status_code == 200
    rules = store.list_rules()
    assert any(r.name == "Test rule" for r in rules)


def test_create_rule_with_invalid_data_shows_errors(client, store):
    before = len(store.list_rules())
    resp = client.post("/rules/new", data={
        "name": "", "action": "bogus", "priority": "-1",
        "source_ip": "nope", "protocol": "ftp", "dest_port": "999999",
    })
    assert resp.status_code == 400
    assert b"required" in resp.data.lower() or b"must be" in resp.data.lower()
    assert len(store.list_rules()) == before  # nothing was created


def test_edit_rule_form_prefills_values(client, store):
    from firewall_sim.models import Rule
    rid = store.add_rule(Rule(id=None, name="Editable", action="allow", priority=5,
                               source_ip="any", protocol="tcp", dest_port="80", enabled=True))
    resp = client.get(f"/rules/{rid}/edit")
    assert resp.status_code == 200
    assert b"Editable" in resp.data


def test_edit_nonexistent_rule_404(client):
    resp = client.get("/rules/9999/edit")
    assert resp.status_code == 404


def test_update_rule_via_post(client, store):
    from firewall_sim.models import Rule
    rid = store.add_rule(Rule(id=None, name="Original", action="allow", priority=5,
                               source_ip="any", protocol="tcp", dest_port="80", enabled=True))
    client.post(f"/rules/{rid}/edit", data={
        "name": "Renamed", "action": "deny", "priority": "20",
        "source_ip": "any", "protocol": "tcp", "dest_port": "80", "enabled": "on",
    })
    rule = store.get_rule(rid)
    assert rule.name == "Renamed"
    assert rule.action == "deny"


def test_delete_rule_via_post(client, store):
    from firewall_sim.models import Rule
    rid = store.add_rule(Rule(id=None, name="ToDelete", action="allow", priority=5,
                               source_ip="any", protocol="tcp", dest_port="80", enabled=True))
    client.post(f"/rules/{rid}/delete")
    assert store.get_rule(rid) is None


def test_toggle_rule_via_post(client, store):
    from firewall_sim.models import Rule
    rid = store.add_rule(Rule(id=None, name="Toggle me", action="allow", priority=5,
                               source_ip="any", protocol="tcp", dest_port="80", enabled=True))
    client.post(f"/rules/{rid}/toggle")
    assert store.get_rule(rid).enabled is False
    client.post(f"/rules/{rid}/toggle")
    assert store.get_rule(rid).enabled is True


# ---------------------------------------------------------------- simulate traffic

def test_simulate_form_renders(client):
    resp = client.get("/simulate")
    assert resp.status_code == 200
    assert b"Simulate traffic" in resp.data


def test_simulate_post_shows_verdict(client):
    resp = client.post("/simulate", data={
        "source_ip": "10.1.1.1", "dest_port": "22", "protocol": "tcp", "description": "",
    })
    assert resp.status_code == 200
    assert b"ALLOW" in resp.data  # matches "Allow internal LAN"
    assert b"Allow internal LAN" in resp.data


def test_simulate_post_logs_an_event(client, store):
    client.post("/simulate", data={
        "source_ip": "198.51.100.66", "dest_port": "31337", "protocol": "tcp", "description": "",
    })
    events = store.list_events()
    assert len(events) == 1
    assert events[0]["action"] == "deny"


def test_simulate_invalid_input_shows_errors(client, store):
    resp = client.post("/simulate", data={
        "source_ip": "any", "dest_port": "443", "protocol": "tcp",
    })
    assert resp.status_code == 400
    assert store.list_events() == []


def test_api_simulate_returns_json(client):
    resp = client.post("/api/simulate", json={
        "source_ip": "203.0.113.55", "dest_port": 3389, "protocol": "tcp",
    })
    assert resp.status_code == 200
    data = json.loads(resp.data)
    assert data["action"] == "deny"
    assert data["matched_rule"]["name"] == "Block RDP from the internet"
    assert len(data["trace"]) >= 1


def test_api_simulate_validation_error(client):
    resp = client.post("/api/simulate", json={"source_ip": "any", "dest_port": 80, "protocol": "tcp"})
    assert resp.status_code == 400
    assert "errors" in json.loads(resp.data)


# ---------------------------------------------------------------- event log

def test_log_page_renders(client):
    resp = client.get("/log")
    assert resp.status_code == 200


def test_log_filter_allow(client):
    client.post("/simulate", data={"source_ip": "10.1.1.1", "dest_port": "22", "protocol": "tcp"})
    client.post("/simulate", data={"source_ip": "198.51.100.66", "dest_port": "31337", "protocol": "tcp"})
    resp = client.get("/log?action=allow")
    assert b"10.1.1.1" in resp.data
    assert b"198.51.100.66" not in resp.data


def test_clear_log(client, store):
    client.post("/simulate", data={"source_ip": "10.1.1.1", "dest_port": "22", "protocol": "tcp"})
    assert len(store.list_events()) == 1
    client.post("/log/clear")
    assert store.list_events() == []


# ---------------------------------------------------------------- settings

def test_settings_page_renders(client):
    resp = client.get("/settings")
    assert resp.status_code == 200


def test_settings_change_default_policy(client, store):
    client.post("/settings", data={"default_policy": "allow"})
    assert store.get_default_policy() == "allow"


# ---------------------------------------------------------------- read-only json api

def test_api_rules(client):
    resp = client.get("/api/rules")
    data = json.loads(resp.data)
    assert isinstance(data, list)
    assert len(data) > 0
    assert "priority" in data[0]


def test_api_log(client):
    client.post("/simulate", data={"source_ip": "10.1.1.1", "dest_port": "22", "protocol": "tcp"})
    resp = client.get("/api/log")
    data = json.loads(resp.data)
    assert len(data) == 1


# ---------------------------------------------------------------- priority end-to-end through the dashboard

def test_priority_change_via_edit_affects_simulation_outcome(client, store):
    """Editing a rule's priority through the web form actually changes
    which rule wins — the same guarantee test_engine.py checks at the
    library level, exercised here through the HTTP layer."""
    from firewall_sim.models import Rule
    deny_id = store.add_rule(Rule(id=None, name="deny ssh", action="deny", priority=5,
                                   source_ip="any", protocol="tcp", dest_port="22", enabled=True))
    allow_id = store.add_rule(Rule(id=None, name="allow ssh", action="allow", priority=50,
                                    source_ip="any", protocol="tcp", dest_port="22", enabled=True))

    resp = client.post("/api/simulate", json={"source_ip": "1.2.3.4", "dest_port": 22, "protocol": "tcp"})
    assert json.loads(resp.data)["matched_rule"]["name"] == "deny ssh"

    # Give "allow ssh" a lower priority number so it now wins.
    client.post(f"/rules/{allow_id}/edit", data={
        "name": "allow ssh", "action": "allow", "priority": "1",
        "source_ip": "any", "protocol": "tcp", "dest_port": "22", "enabled": "on",
    })

    resp = client.post("/api/simulate", json={"source_ip": "1.2.3.4", "dest_port": 22, "protocol": "tcp"})
    assert json.loads(resp.data)["matched_rule"]["name"] == "allow ssh"
