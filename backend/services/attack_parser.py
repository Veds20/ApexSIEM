"""
attack_parser.py — Multi-format log line parser
Handles: app.log simulator format, auth.log, syslog, generic IP extraction
"""

import re


# Supported attack type labels (canonical names used throughout the system)
KNOWN_ATTACK_TYPES = {
    "brute_force", "malware", "port_scan", "normal",
    "privilege_escalation", "suspicious_sudo", "failed_login",
    "account_lockout", "rdp_attack", "ssh_attack", "unknown"
}


def parse_log_line(line: str) -> dict | None:
    """
    Parse a log line and return a normalized alert dict or None.

    Tries parsers in this order:
      1. Simulator format  →  [timestamp] IP=x TYPE=y STATUS=z
      2. Auth.log format   →  Failed password / Accepted / sudo
      3. Syslog/UFW format →  UFW BLOCK SRC=x DPT=y
      4. Generic fallback  →  Any line with an IP + threat keyword
    """
    return (
        _parse_simulator(line)
        or _parse_auth_log(line)
        or _parse_syslog(line)
        or _parse_generic(line)
    )


# ======================================================
# PARSER 1 — Simulator / app.log format
# ======================================================

def _parse_simulator(line: str) -> dict | None:
    """
    Expected format:
    [2026-03-03 12:10:22] IP=192.168.1.45 TYPE=brute_force STATUS=failed
    """
    pattern = r"IP=([\d.]+)\s+TYPE=(\S+)\s+STATUS=(\S+)"
    m = re.search(pattern, line)
    if not m:
        return None

    attack_type = m.group(2)
    if attack_type not in KNOWN_ATTACK_TYPES:
        attack_type = "unknown"

    return {
        "source_ip": m.group(1),
        "attack_type": attack_type,
    }


# ======================================================
# PARSER 2 — Linux auth.log / /var/log/secure
# ======================================================

def _parse_auth_log(line: str) -> dict | None:
    """
    Handles common SSH and PAM log patterns.
    """
    # SSH: Failed password
    m = re.search(
        r"Failed password for (?:invalid user )?(\S+) from ([\d.]+)",
        line
    )
    if m:
        return {
            "source_ip": m.group(2),
            "attack_type": "brute_force" if "invalid user" in line else "failed_login",
        }

    # SSH: Accepted login (normal traffic)
    m = re.search(r"Accepted \S+ for \S+ from ([\d.]+)", line)
    if m:
        return {"source_ip": m.group(1), "attack_type": "normal"}

    # Sudo abuse / privilege escalation
    if "sudo" in line:
        if "authentication failure" in line or "3 incorrect password" in line:
            return {"source_ip": _extract_ip(line) or "127.0.0.1", "attack_type": "suspicious_sudo"}
        if "COMMAND=" in line:
            return {"source_ip": _extract_ip(line) or "127.0.0.1", "attack_type": "privilege_escalation"}

    # Account lockout (pam_tally2 / faillock)
    if any(kw in line for kw in ("pam_tally", "account locked", "FAILED LOGIN", "User not known")):
        return {"source_ip": _extract_ip(line) or "127.0.0.1", "attack_type": "account_lockout"}

    return None


# ======================================================
# PARSER 3 — Syslog / UFW / iptables
# ======================================================

def _parse_syslog(line: str) -> dict | None:
    """
    Handles firewall drop messages and kernel events.
    """
    # UFW BLOCK (Ubuntu default firewall)
    m = re.search(r"\[UFW BLOCK\].*?SRC=([\d.]+)", line)
    if m:
        return {"source_ip": m.group(1), "attack_type": "port_scan"}

    # Generic iptables DROP
    m = re.search(r"kernel:.*?DROP.*?SRC=([\d.]+)", line)
    if m:
        return {"source_ip": m.group(1), "attack_type": "port_scan"}

    # nmap-style OS fingerprint attempt
    if "nmap" in line.lower() or "XMAS" in line or "FIN scan" in line:
        ip = _extract_ip(line) or "0.0.0.0"
        return {"source_ip": ip, "attack_type": "port_scan"}

    return None


# ======================================================
# PARSER 4 — Generic keyword-based fallback
# ======================================================

_KEYWORD_MAP = [
    (r"brute.?force|repeated.?fail", "brute_force"),
    (r"malware|trojan|ransomware|virus", "malware"),
    (r"port.?scan|nmap|masscan", "port_scan"),
    (r"rdp.*fail|3389", "rdp_attack"),
    (r"ssh.*fail|22\b", "ssh_attack"),
    (r"privilege|escalat|root.?access", "privilege_escalation"),
]


def _parse_generic(line: str) -> dict | None:
    """
    Last-resort parser: look for threat keywords + an IP address.
    Only triggers if an IP is present (avoids false positives on pure text).
    """
    ip = _extract_ip(line)
    if not ip:
        return None

    lower = line.lower()
    for pattern, attack_type in _KEYWORD_MAP:
        if re.search(pattern, lower):
            return {"source_ip": ip, "attack_type": attack_type}

    return None


# ======================================================
# HELPERS
# ======================================================

def _extract_ip(line: str) -> str | None:
    """Return the first valid public-ish IPv4 from a log line."""
    matches = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    for m in matches:
        parts = m.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            # Skip loopback / unroutable
            if m not in ("0.0.0.0", "255.255.255.255") and not m.startswith("127."):
                return m
    return None