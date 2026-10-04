"""
sample_data.py — the rules and traffic the dashboard ships with, so
there's something meaningful to look at (and test against) immediately.

Every IP address here is either RFC 1918 private space (10.0.0.0/8 —
the "internal network") or RFC 5737 documentation space
(203.0.113.0/24, 198.51.100.0/24 — reserved specifically for examples
like this) — none of it is a real, reachable host.
"""

# Evaluated in priority order (lower number first). See README for a
# walkthrough of exactly which sample traffic hits which rule, and why
# the ORDER of these rules — not just their existence — matters.
DEFAULT_RULES = [
    dict(
        name="Allow internal LAN", action="allow", priority=10,
        source_ip="10.0.0.0/8", protocol="any", dest_port="any", enabled=True,
        description="Trust all traffic originating from the internal network.",
    ),
    dict(
        name="Allow HTTPS", action="allow", priority=20,
        source_ip="any", protocol="tcp", dest_port="443", enabled=True,
        description="Allow inbound HTTPS from anywhere.",
    ),
    dict(
        name="Allow DNS", action="allow", priority=30,
        source_ip="any", protocol="udp", dest_port="53", enabled=True,
        description="Allow DNS queries.",
    ),
    dict(
        name="Block known-bad host", action="deny", priority=40,
        source_ip="198.51.100.66", protocol="any", dest_port="any", enabled=True,
        description="Blocklisted source (example malicious host, RFC 5737 doc range).",
    ),
    dict(
        name="Block RDP from the internet", action="deny", priority=50,
        source_ip="any", protocol="tcp", dest_port="3389", enabled=True,
        description="Remote Desktop should never be exposed to the open internet.",
    ),
]

# Named, ready-to-submit sample traffic for the "Simulate traffic" page.
SAMPLE_TRAFFIC = [
    dict(
        name="Internal SSH session", source_ip="10.0.0.5", dest_port=22, protocol="tcp",
        description="An internal machine opening an SSH connection.",
    ),
    dict(
        name="Internal web app (port 8080)", source_ip="10.0.0.20", dest_port=8080, protocol="tcp",
        description="Internal traffic to a non-standard web port.",
    ),
    dict(
        name="Office HTTPS request", source_ip="203.0.113.10", dest_port=443, protocol="tcp",
        description="An external client making an HTTPS request.",
    ),
    dict(
        name="DNS query from internal resolver", source_ip="10.0.0.1", dest_port=53, protocol="udp",
        description="Internal DNS traffic — note this is caught by the internal-LAN rule before it "
                     "ever reaches the more specific 'Allow DNS' rule.",
    ),
    dict(
        name="Suspicious port probe", source_ip="198.51.100.66", dest_port=31337, protocol="tcp",
        description="A known-bad external host probing an unusual port.",
    ),
    dict(
        name="Ping sweep from known-bad host", source_ip="198.51.100.66", dest_port=0, protocol="icmp",
        description="ICMP echo request from the same blocklisted host.",
    ),
    dict(
        name="External RDP attempt", source_ip="203.0.113.55", dest_port=3389, protocol="tcp",
        description="An external host trying to reach RDP.",
    ),
    dict(
        name="Unclassified external traffic", source_ip="203.0.113.99", dest_port=8443, protocol="tcp",
        description="Doesn't match any rule — this one falls through to the default policy.",
    ),
]
