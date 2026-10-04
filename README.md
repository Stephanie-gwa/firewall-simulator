# firewall-sim

A firewall **rule simulator** with a Flask web dashboard. Create allow/deny
rules keyed on source IP, destination port, and protocol; submit simulated
traffic; and see exactly which rule matched — and why — via a full,
step-by-step evaluation trace.

## ⚠️ This is a simulation

**This project never touches your computer's real firewall, network
configuration, or any actual network traffic.** There is no `iptables`,
`pf`, Windows Firewall, or raw socket code anywhere in this repository.
Rules live in a local SQLite file; "traffic" is a form field you type in
or a JSON POST you send; "matching" is pure Python string/CIDR/range
comparison. It is a teaching and portfolio tool for understanding how
rule-based firewalls decide allow vs. deny — not a firewall.

## Features

- **Rules** with source IP (exact, CIDR, or `any`), destination port
  (exact, range, or `any`), protocol (`tcp`/`udp`/`icmp`/`any`), an
  `allow`/`deny` action, an enabled/disabled toggle, and a **priority**
  that controls evaluation order.
- **First-match-wins evaluation** (like iptables and most real
  firewalls): rules are checked in priority order, lowest number first;
  the first enabled rule that matches every dimension decides the
  outcome, and evaluation stops there.
- **A configurable default policy** (`allow` or `deny`) applied when no
  rule matches.
- **A full evaluation trace** for every simulated packet — not just the
  final verdict, but every rule that was checked, whether it matched,
  and precisely why (or why not).
- **An event log** of every simulated packet, filterable by allow/deny.
- **Sample data**: five seeded rules and eight named sample traffic
  scenarios, chosen to demonstrate priority ordering, the default
  policy, and a blocklisted host — not just "happy path" allows.
- A small **JSON API** (`/api/simulate`, `/api/rules`, `/api/log`)
  alongside the HTML dashboard.
- 106 automated tests, with the matching/priority logic tested
  independently of the web layer.

## Project layout

```
firewall_sim/
  models.py          Rule, Packet, TraceEntry, EvaluationResult
  validation.py         Field validation (shared by the web forms and tests)
  matcher.py              IP/CIDR, port/range, and protocol matching — with reasons
  engine.py                 Priority-ordered, first-match-wins evaluation
  store.py                    SQLite persistence: rules, default policy, event log
  sample_data.py                 Seeded rules + named sample traffic
  webapp.py                        Flask app factory — all dashboard routes + JSON API
  templates/, static/                HTML + CSS for the dashboard
tests/
  test_matcher.py, test_engine.py, test_store.py, test_validation.py, test_webapp.py
examples/
  sample_rules.json, sample_event_log.json     Real output from a sample run
run.py                                           Entry point
```

## Setup

Requires Python 3.9+.

```bash
git clone <this-repo>
cd firewall-simulator
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install -r requirements-dev.txt   # only needed to run the tests
```

## Run it

```bash
python run.py
```

```
Firewall simulator dashboard running at http://127.0.0.1:5050
Simulation only — no real firewall or network configuration is touched.
```

Open **http://127.0.0.1:5050**. The database (`firewall_sim.db`, created
in the current directory) is seeded with 5 sample rules on first run.

Environment variables: `HOST` (default `127.0.0.1`), `PORT` (default
`5050`), `DB_PATH` (default `firewall_sim.db`).

### Using it

1. **Rules** (the home page) — see every rule in evaluation order, with
   its priority, action, and match criteria. Create, edit, enable/disable,
   or delete rules here.
2. **Simulate Traffic** — pick a sample scenario or type your own
   source IP / port / protocol, submit it, and see the verdict plus the
   full rule-by-rule trace.
3. **Event Log** — every simulated packet, with the matched rule (or
   "default policy"), filterable by allow/deny.
4. **Settings** — change the default policy.

### JSON API

```bash
curl -X POST http://127.0.0.1:5050/api/simulate \
  -H "Content-Type: application/json" \
  -d '{"source_ip": "198.51.100.66", "dest_port": 31337, "protocol": "tcp"}'

curl http://127.0.0.1:5050/api/rules
curl http://127.0.0.1:5050/api/log
```

## How matching and priority actually work

Rules are sorted by **priority ascending** (lower number = evaluated
first), with ties broken by rule creation order. The engine walks that
list; the first **enabled** rule whose source IP, protocol, *and*
destination port all match wins, and no further rules are checked. If
nothing matches, the **default policy** applies.

A rule matches a packet only if all three dimensions match:

| Field | Rule syntax | Matches |
|---|---|---|
| Source IP | `any`, `10.1.2.3`, or `10.0.0.0/8` | exact address or CIDR membership |
| Protocol | `any`, `tcp`, `udp`, `icmp` | exact match (ICMP traffic ignores the port dimension entirely — ICMP has no ports) |
| Dest. port | `any`, `443`, or `8000-8100` | exact value or inclusive range |

### Why priority order matters — a worked example

The seeded rules include, in order:

```
priority 10   Allow internal LAN     source 10.0.0.0/8, any protocol, any port  → allow
priority 20   Allow HTTPS            any source, tcp, port 443                   → allow
priority 30   Allow DNS              any source, udp, port 53                    → allow
priority 40   Block known-bad host   source 198.51.100.66, any protocol/port     → deny
priority 50   Block RDP              any source, tcp, port 3389                  → deny
```

Simulate **"DNS query from internal resolver"** (`10.0.0.1`, UDP, port
53) and the trace shows it's allowed by **"Allow internal LAN"** at
priority 10 — not by the more specific **"Allow DNS"** rule at priority
30, which is never even reached. Moving "Allow DNS" to a *lower*
priority number than "Allow internal LAN" would change nothing here (LAN
traffic would still match either rule the same way), but the reverse
matters a great deal for e.g. a **deny** rule: a broad low-priority-number
allow can silently shadow a more specific deny rule ranked below it. This
is exactly the kind of rule-ordering mistake that causes real firewall
misconfigurations, and it's why the dashboard always shows the *whole*
trace, not just the final verdict.

## Sample data walkthrough

All 8 sample traffic scenarios and their outcomes against the seeded
rules (verified in `tests/test_engine.py::test_sample_rule_set_matches_expected_outcomes`
and reproduced for real in `examples/sample_event_log.json`):

| Scenario | Result | Matched |
|---|---|---|
| Internal SSH session (`10.0.0.5`, tcp/22) | **allow** | Allow internal LAN |
| Internal web app (`10.0.0.20`, tcp/8080) | **allow** | Allow internal LAN |
| Office HTTPS request (`203.0.113.10`, tcp/443) | **allow** | Allow HTTPS |
| DNS query from internal resolver (`10.0.0.1`, udp/53) | **allow** | Allow internal LAN (see above) |
| Suspicious port probe (`198.51.100.66`, tcp/31337) | **deny** | Block known-bad host |
| Ping sweep from known-bad host (`198.51.100.66`, icmp) | **deny** | Block known-bad host |
| External RDP attempt (`203.0.113.55`, tcp/3389) | **deny** | Block RDP from the internet |
| Unclassified external traffic (`203.0.113.99`, tcp/8443) | **deny** | *(default policy — no rule matched)* |

Every IP in the sample data and seeded rules is either RFC 1918 private
space (`10.0.0.0/8`) or RFC 5737 documentation space
(`203.0.113.0/24`, `198.51.100.0/24`) — none of it is a real host.

## Running the tests

```bash
pip install -r requirements-dev.txt
python -m pytest -v
```

**106/106 tests pass** on a clean checkout:

- `test_matcher.py` — IP/CIDR matching, port/range matching, protocol
  matching, and combined rule matching, including edge cases (CIDR
  boundaries, `/32` single-host networks, ICMP's port-independence,
  malformed rule fields).
- `test_engine.py` — first-match-wins, priority ordering independent of
  insertion order, tie-breaking, disabled rules, the default-policy
  fallback, full trace correctness, and the complete sample-data
  scenario end to end.
- `test_store.py` — SQLite-backed rule CRUD, settings, and event log.
- `test_validation.py` — every field validator, both valid and invalid
  inputs.
- `test_webapp.py` — every dashboard route and the JSON API, using
  Flask's test client (in-process, no real server needed), including a
  test that edits a rule's priority through the actual HTTP form and
  confirms the simulated outcome changes accordingly.

## Limitations

- **Not a real firewall.** It doesn't inspect real packets, doesn't run
  with elevated privileges, and doesn't persist rules anywhere your OS's
  networking stack would ever read them.
- **Stateless matching only.** No connection tracking, no "established/
  related" rules, no NAT, no rate limiting — each simulated packet is
  evaluated independently.
- **IPv4 only.** IPv6 addresses aren't supported by the validator or matcher.
- **Single destination context.** Rules don't model a specific network
  interface or destination IP — only source IP, protocol, and
  destination port, matching the scope asked for.
- **First match wins, always.** There's no rule "grouping", "continue"
  action, or logging-only rule type — a rule is either the decisive
  match or it isn't checked at all once an earlier one matches.

## Portfolio description

> **firewall-sim** — A firewall rule-matching engine and Flask web
> dashboard, built to make firewall priority semantics visible rather
> than opaque. Supports source-IP (CIDR-aware), destination-port
> (range-aware), and protocol-based allow/deny rules with configurable
> priority and a default policy; every simulated packet returns a full,
> rule-by-rule evaluation trace, not just a final verdict. Backed by
> SQLite, with an included worked example demonstrating a classic
> rule-ordering pitfall (a broad low-priority-number allow silently
> shadowing a more specific rule below it). 106 tests, including
> priority-ordering and tie-breaking behavior verified independently of
> the web layer, plus HTTP-level tests confirming a priority edit made
> through the dashboard actually changes simulation outcomes. This is a
> simulator — it does not touch any real firewall or network configuration.

**Technologies used:** Python 3, Flask, SQLite (`sqlite3`), Jinja2,
`ipaddress` (CIDR matching), `dataclasses`; `pytest` for testing
(including Flask's test client for in-process HTTP tests);
`pyproject.toml`/`setuptools` for packaging.

**Dashboard screenshot ideas:**
- The **Rules** page with all 5 seeded rules visible, priority column
  prominent, so a viewer can see the ordering at a glance.
- The **Simulate Traffic** page after submitting "Suspicious port
  probe" — the red DENY verdict next to the full evaluation trace
  table, with the matching row highlighted.
- The same page after submitting "DNS query from internal resolver" —
  a good screenshot specifically *because* it's allowed by the LAN rule
  and not the DNS rule, visually proving the priority-shadowing point
  from the README.
- The **Event Log** filtered to "Denied" only, showing the blocklisted
  host and the RDP attempt side by side.
- A before/after pair: editing "Allow DNS"'s priority number lower than
  "Allow internal LAN" and re-running the DNS scenario to show the
  matched rule change in the trace.

## License

MIT — see `LICENSE`.
