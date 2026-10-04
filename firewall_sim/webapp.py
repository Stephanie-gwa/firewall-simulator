"""
webapp.py — the Flask dashboard. A thin UI/API layer over engine.py /
store.py; all the actual rule-matching logic lives there, not here.

create_app(db_path) is a factory so tests can build an app backed by an
in-memory database, independent of any file on disk.
"""
from __future__ import annotations
import os

from flask import Flask, jsonify, redirect, render_template, request, url_for

from .engine import FirewallEngine
from .models import Packet, Rule
from .sample_data import DEFAULT_RULES, SAMPLE_TRAFFIC
from .store import Store
from .validation import validate_packet_fields, validate_rule_fields


def create_app(db_path: str = "firewall_sim.db", seed: bool = True) -> Flask:
    app = Flask(__name__)
    store = Store(db_path)
    if seed:
        store.seed_if_empty(DEFAULT_RULES)
    engine = FirewallEngine(store)

    app.config["STORE"] = store
    app.config["ENGINE"] = engine

    # -------------------------------------------------------------- dashboard

    @app.route("/")
    def dashboard():
        rules = store.list_rules()
        counts = store.event_counts()
        recent = store.list_events(limit=10)
        return render_template(
            "dashboard.html", rules=rules, counts=counts, recent=recent,
            default_policy=store.get_default_policy(),
        )

    # -------------------------------------------------------------- rules

    @app.route("/rules/new", methods=["GET", "POST"])
    def new_rule():
        if request.method == "GET":
            return render_template("rule_form.html", rule=None, errors={}, values={})

        values = _rule_form_values(request.form)
        errors = validate_rule_fields(values)
        if errors:
            return render_template("rule_form.html", rule=None, errors=errors, values=values), 400

        store.add_rule(Rule(
            id=None, name=values["name"], action=values["action"], priority=int(values["priority"]),
            source_ip=values["source_ip"], protocol=values["protocol"], dest_port=values["dest_port"],
            enabled=values.get("enabled") == "on", description=values.get("description", ""),
        ))
        return redirect(url_for("dashboard"))

    @app.route("/rules/<int:rule_id>/edit", methods=["GET", "POST"])
    def edit_rule(rule_id):
        rule = store.get_rule(rule_id)
        if rule is None:
            return render_template("error.html", message=f"Rule #{rule_id} not found."), 404

        if request.method == "GET":
            return render_template("rule_form.html", rule=rule, errors={}, values=rule.to_dict())

        values = _rule_form_values(request.form)
        errors = validate_rule_fields(values)
        if errors:
            return render_template("rule_form.html", rule=rule, errors=errors, values=values), 400

        store.update_rule(
            rule_id, name=values["name"], action=values["action"], priority=int(values["priority"]),
            source_ip=values["source_ip"], protocol=values["protocol"], dest_port=values["dest_port"],
            enabled=values.get("enabled") == "on", description=values.get("description", ""),
        )
        return redirect(url_for("dashboard"))

    @app.route("/rules/<int:rule_id>/delete", methods=["POST"])
    def delete_rule(rule_id):
        store.delete_rule(rule_id)
        return redirect(url_for("dashboard"))

    @app.route("/rules/<int:rule_id>/toggle", methods=["POST"])
    def toggle_rule(rule_id):
        rule = store.get_rule(rule_id)
        if rule is not None:
            store.set_rule_enabled(rule_id, not rule.enabled)
        return redirect(url_for("dashboard"))

    # -------------------------------------------------------------- simulate traffic

    @app.route("/simulate", methods=["GET", "POST"])
    def simulate():
        if request.method == "GET":
            return render_template("simulate.html", samples=SAMPLE_TRAFFIC, result=None, errors={}, values={})

        values = {
            "source_ip": request.form.get("source_ip", "").strip(),
            "dest_port": request.form.get("dest_port", "").strip(),
            "protocol": request.form.get("protocol", "").strip(),
        }
        description = request.form.get("description", "").strip()
        errors = validate_packet_fields(values)
        if errors:
            return render_template("simulate.html", samples=SAMPLE_TRAFFIC, result=None,
                                    errors=errors, values=values), 400

        packet = Packet(
            source_ip=values["source_ip"], dest_port=int(values["dest_port"]),
            protocol=values["protocol"], description=description,
        )
        result = engine.evaluate(packet)
        return render_template("simulate.html", samples=SAMPLE_TRAFFIC, result=result,
                                errors={}, values=values)

    @app.route("/api/simulate", methods=["POST"])
    def api_simulate():
        data = request.get_json(force=True) or {}
        values = {
            "source_ip": str(data.get("source_ip", "")).strip(),
            "dest_port": str(data.get("dest_port", "")).strip(),
            "protocol": str(data.get("protocol", "")).strip(),
        }
        errors = validate_packet_fields(values)
        if errors:
            return jsonify({"errors": errors}), 400
        packet = Packet(
            source_ip=values["source_ip"], dest_port=int(values["dest_port"]),
            protocol=values["protocol"], description=str(data.get("description", "")),
        )
        result = engine.evaluate(packet)
        return jsonify(result.to_dict())

    # -------------------------------------------------------------- event log

    @app.route("/log")
    def event_log():
        action_filter = request.args.get("action") or None
        limit = int(request.args.get("limit", 100))
        events = store.list_events(limit=limit)
        if action_filter in ("allow", "deny"):
            events = [e for e in events if e["action"] == action_filter]
        return render_template("log.html", events=events, action_filter=action_filter)

    @app.route("/log/clear", methods=["POST"])
    def clear_log():
        store.clear_events()
        return redirect(url_for("event_log"))

    # -------------------------------------------------------------- settings

    @app.route("/settings", methods=["GET", "POST"])
    def settings():
        if request.method == "POST":
            policy = request.form.get("default_policy")
            if policy in ("allow", "deny"):
                store.set_default_policy(policy)
            return redirect(url_for("settings"))
        return render_template("settings.html", default_policy=store.get_default_policy())

    # -------------------------------------------------------------- json api (read-only)

    @app.route("/api/rules")
    def api_rules():
        return jsonify([r.to_dict() for r in store.list_rules()])

    @app.route("/api/log")
    def api_log():
        return jsonify(store.list_events(limit=int(request.args.get("limit", 50))))

    return app


def _rule_form_values(form) -> dict:
    return {
        "name": form.get("name", "").strip(),
        "action": form.get("action", "").strip(),
        "priority": form.get("priority", "").strip(),
        "source_ip": form.get("source_ip", "").strip(),
        "protocol": form.get("protocol", "").strip(),
        "dest_port": form.get("dest_port", "").strip(),
        "enabled": form.get("enabled", ""),
        "description": form.get("description", "").strip(),
    }


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "5050"))
    db_path = os.environ.get("DB_PATH", "firewall_sim.db")
    application = create_app(db_path)
    print(f"Firewall simulator dashboard running at http://{host}:{port}  (simulation only — "
          f"no real firewall is touched)")
    application.run(host=host, port=port, debug=False)
