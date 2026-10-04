"""
store.py — persistence. Rules, the default-policy setting, and the
event log all live in a small SQLite database (a single file, or
:memory: for tests). No network access, no real firewall of any kind
is touched here — this only ever reads and writes the simulator's own
local database file.
"""
from __future__ import annotations
import datetime
import sqlite3
from typing import Optional

from .models import EvaluationResult, Packet, Rule

SCHEMA = """
CREATE TABLE IF NOT EXISTS rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    action TEXT NOT NULL,
    priority INTEGER NOT NULL,
    source_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    dest_port TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS event_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    dest_port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    action TEXT NOT NULL,
    matched_rule_id INTEGER,
    matched_rule_name TEXT,
    used_default INTEGER NOT NULL,
    reason_summary TEXT NOT NULL
);
"""

DEFAULT_POLICY_KEY = "default_policy"


def _row_to_rule(row: sqlite3.Row) -> Rule:
    return Rule(
        id=row["id"], name=row["name"], action=row["action"], priority=row["priority"],
        source_ip=row["source_ip"], protocol=row["protocol"], dest_port=row["dest_port"],
        enabled=bool(row["enabled"]), description=row["description"],
    )


class Store:
    def __init__(self, path: str = ":memory:"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        if self.get_default_policy() is None:
            self.set_default_policy("deny")

    # ---------------------------------------------------------- rules
    def add_rule(self, rule: Rule) -> int:
        cur = self.conn.execute(
            "INSERT INTO rules (name, action, priority, source_ip, protocol, dest_port, enabled, description) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (rule.name, rule.action, rule.priority, rule.source_ip, rule.protocol,
             rule.dest_port, int(rule.enabled), rule.description),
        )
        self.conn.commit()
        return cur.lastrowid

    def update_rule(self, rule_id: int, **fields) -> None:
        if not fields:
            return
        if "enabled" in fields:
            fields["enabled"] = int(fields["enabled"])
        columns = ", ".join(f"{k} = ?" for k in fields)
        values = list(fields.values()) + [rule_id]
        self.conn.execute(f"UPDATE rules SET {columns} WHERE id = ?", values)
        self.conn.commit()

    def delete_rule(self, rule_id: int) -> None:
        self.conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        self.conn.commit()

    def get_rule(self, rule_id: int) -> Optional[Rule]:
        row = self.conn.execute("SELECT * FROM rules WHERE id = ?", (rule_id,)).fetchone()
        return _row_to_rule(row) if row else None

    def list_rules(self, enabled_only: bool = False) -> list:
        sql = "SELECT * FROM rules"
        if enabled_only:
            sql += " WHERE enabled = 1"
        sql += " ORDER BY priority ASC, id ASC"
        return [_row_to_rule(r) for r in self.conn.execute(sql).fetchall()]

    def set_rule_enabled(self, rule_id: int, enabled: bool) -> None:
        self.update_rule(rule_id, enabled=enabled)

    # ---------------------------------------------------------- settings
    def get_default_policy(self) -> Optional[str]:
        row = self.conn.execute(
            "SELECT value FROM settings WHERE key = ?", (DEFAULT_POLICY_KEY,)
        ).fetchone()
        return row["value"] if row else None

    def set_default_policy(self, policy: str) -> None:
        self.conn.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (DEFAULT_POLICY_KEY, policy),
        )
        self.conn.commit()

    # ---------------------------------------------------------- event log
    def log_event(self, packet: Packet, result: EvaluationResult) -> int:
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        result.timestamp = timestamp
        cur = self.conn.execute(
            "INSERT INTO event_log (timestamp, source_ip, dest_port, protocol, description, "
            "action, matched_rule_id, matched_rule_name, used_default, reason_summary) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                timestamp, packet.source_ip, packet.dest_port, packet.protocol, packet.description,
                result.action,
                result.matched_rule.id if result.matched_rule else None,
                result.matched_rule.name if result.matched_rule else None,
                int(result.used_default), result.reason_summary,
            ),
        )
        self.conn.commit()
        return cur.lastrowid

    def list_events(self, limit: int = 50) -> list:
        rows = self.conn.execute(
            "SELECT * FROM event_log ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    def clear_events(self) -> None:
        self.conn.execute("DELETE FROM event_log")
        self.conn.commit()

    def event_counts(self) -> dict:
        rows = self.conn.execute(
            "SELECT action, COUNT(*) as n FROM event_log GROUP BY action"
        ).fetchall()
        counts = {"allow": 0, "deny": 0}
        for r in rows:
            counts[r["action"]] = r["n"]
        return counts

    # ---------------------------------------------------------- seeding
    def seed_if_empty(self, rules: list) -> None:
        if self.list_rules():
            return
        for rule_dict in rules:
            self.add_rule(Rule(id=None, **rule_dict))
