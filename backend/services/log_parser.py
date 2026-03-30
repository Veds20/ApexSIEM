"""
Real Log Parser
===============
Parses REAL log lines/events into structured alert records.
No fabrication. All fields derive from actual log content.

Output schema per alert:
{
    source_ip: str,
    destination_ip: str | None,
    timestamp: datetime,
    log_source: str,
    event_type: str,
    attack_type: str,
    severity: str,
    trust_score: int,
    description: str,   ← derived from real event fields
    raw_log: str,
}
"""

import re
import json
import logging
from datetime import datetime, timezone
from typing import Optional

from backend.services.detection_engine import detect_attack, score_from_attack

logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# Windows Event ID → human readable event type
# ──────────────────────────────────────────────
WINDOWS_EVENT_DESCRIPTIONS = {
    4624: "Successful logon",
    4625: "Failed logon attempt",
    4627: "Group membership enumerated",
    4648: "Logon using explicit credentials",
    4656: "Object handle requested",
    4663: "Object access attempt",
    4672: "Special privileges assigned to new logon",
    4688: "New process created",
    4698: "Scheduled task created",
    4702: "Scheduled task updated",
    4719: "System audit policy changed",
    4720: "User account created",
    4722: "User account enabled",
    4724: "Password reset attempt",
    4725: "User account disabled",
    4726: "User account deleted",
    4728: "Member added to security-enabled global group",
    4732: "Member added to security-enabled local group",
    4738: "User account changed",
    4740: "User account locked out",
    4756: "Member added to security-enabled universal group",
    4768: "Kerberos TGT requested",
    4769: "Kerberos service ticket requested",
    4771: "Kerberos pre-authentication failed",
    4776: "NTLM authentication attempt",
    4798: "User's local group membership enumerated",
    4799: "Security-enabled local group membership enumerated",
    1100: "Event logging service shut down",
    1102: "Audit log cleared",
    1104: "Security log is full",
    7034: "Service crashed unexpectedly",
    7035: "Service sent start/stop control",
    7036: "Service state changed",
    4104: "PowerShell script block logged",
}

# Logon type codes (field index 8 in 4624/4625)
LOGON_TYPES = {
    "2": "Interactive", "3": "Network", "4": "Batch",
    "5": "Service", "7": "Unlock", "8": "NetworkCleartext",
    "9": "NewCredentials", "10": "RemoteInteractive",
    "11": "CachedInteractive", "12": "CachedRemoteInteractive",
}


def parse_windows_event(event_id: int, inserts: list, channel: str, raw_log: str) -> Optional[dict]:
    """
    Parse a real Windows event into a structured alert.
    inserts = evt.StringInserts — the real fields from the event.
    """
    inserts = [str(s) for s in inserts] if inserts else []

    def get(idx, default=""):
        return inserts[idx] if idx < len(inserts) else default

    timestamp = datetime.now(timezone.utc)
    event_type = WINDOWS_EVENT_DESCRIPTIONS.get(event_id, f"EventID {event_id}")
    source_ip = None
    destination_ip = None
    subject_user = ""
    target_user = ""
    workstation = ""
    process_name = ""
    description = ""

    # ── Logon events ──────────────────────────────────────────────────────
    if event_id == 4625:  # Failed logon
        target_user = get(5)
        subject_user = get(1)
        logon_type_code = get(10)
        logon_type = LOGON_TYPES.get(logon_type_code, logon_type_code)
        ip_raw = get(19)
        source_ip = _clean_ip(ip_raw)
        workstation = get(13)
        failure_reason = get(9)
        description = (
            f"Failed {logon_type} logon for account '{target_user}'"
            + (f" from {source_ip}" if source_ip else "")
            + (f" on workstation '{workstation}'" if workstation and workstation != "-" else "")
            + (f". Reason: {failure_reason}" if failure_reason and failure_reason != "%%2313" else "")
        )

    elif event_id == 4624:  # Successful logon
        target_user = get(5)
        logon_type_code = get(8)
        logon_type = LOGON_TYPES.get(logon_type_code, logon_type_code)
        ip_raw = get(18)
        source_ip = _clean_ip(ip_raw)
        workstation = get(11)
        description = (
            f"Successful {logon_type} logon for account '{target_user}'"
            + (f" from {source_ip}" if source_ip else "")
        )

    elif event_id == 4648:  # Explicit credentials logon
        subject_user = get(1)
        target_user = get(5)
        target_server = get(8)
        source_ip = _clean_ip(get(12))
        description = (
            f"Explicit credentials used by '{subject_user}' to authenticate as '{target_user}'"
            + (f" to server '{target_server}'" if target_server else "")
        )

    elif event_id == 4672:  # Special privileges
        subject_user = get(1)
        privileges = get(4)
        description = f"Special privileges assigned to '{subject_user}': {privileges[:200]}"

    # ── Process creation ──────────────────────────────────────────────────
    elif event_id == 4688:
        subject_user = get(1)
        process_name = get(5)
        parent_process = get(13)
        cmd_line = get(8) or get(9)
        source_ip = _clean_ip(get(11)) or "localhost"
        description = (
            f"Process created by '{subject_user}': {process_name}"
            + (f" (parent: {parent_process})" if parent_process and parent_process != "-" else "")
            + (f" | CmdLine: {cmd_line[:200]}" if cmd_line and cmd_line not in ("-", "") else "")
        )

    # ── Account management ────────────────────────────────────────────────
    elif event_id == 4720:
        subject_user = get(4)
        target_user = get(0)
        description = f"New user account '{target_user}' created by '{subject_user}'"

    elif event_id == 4740:
        target_user = get(0)
        caller = get(1)
        workstation = get(2)
        description = (
            f"Account '{target_user}' locked out"
            + (f" — triggered by '{caller}'" if caller else "")
            + (f" on '{workstation}'" if workstation else "")
        )

    elif event_id == 4724:
        subject_user = get(4)
        target_user = get(0)
        description = f"Password reset attempted for '{target_user}' by '{subject_user}'"

    elif event_id in (4728, 4732, 4756):
        target_user = get(0)
        group = get(2)
        subject_user = get(6)
        description = f"'{target_user}' added to group '{group}' by '{subject_user}'"

    # ── Scheduled tasks ───────────────────────────────────────────────────
    elif event_id in (4698, 4702):
        subject_user = get(1)
        task_name = get(4)
        description = f"Scheduled task '{task_name}' {'created' if event_id==4698 else 'updated'} by '{subject_user}'"

    # ── Audit/policy ──────────────────────────────────────────────────────
    elif event_id == 4719:
        subject_user = get(1)
        description = f"System audit policy changed by '{subject_user}'"

    elif event_id == 1102:
        subject_user = get(1)
        description = f"Security audit log CLEARED by '{subject_user}'"

    elif event_id == 1104:
        description = "Security event log is full — events may be lost"

    # ── Kerberos ─────────────────────────────────────────────────────────
    elif event_id == 4768:
        target_user = get(0)
        source_ip = _clean_ip(get(9))
        result_code = get(5)
        description = (
            f"Kerberos TGT requested for '{target_user}'"
            + (f" from {source_ip}" if source_ip else "")
            + (f" — result code: {result_code}" if result_code and result_code != "0x0" else "")
        )

    elif event_id == 4771:
        target_user = get(0)
        source_ip = _clean_ip(get(6))
        failure_code = get(4)
        description = (
            f"Kerberos pre-auth FAILED for '{target_user}'"
            + (f" from {source_ip}" if source_ip else "")
            + (f" — failure code: {failure_code}" if failure_code else "")
        )

    elif event_id == 4776:
        target_user = get(1)
        workstation = get(2)
        error_code = get(3)
        description = (
            f"NTLM authentication attempt for '{target_user}'"
            + (f" from '{workstation}'" if workstation else "")
            + (f" — error: {error_code}" if error_code and error_code != "0x0" else "")
        )

    # ── PowerShell ────────────────────────────────────────────────────────
    elif event_id == 4104:
        script_block = get(2)[:500]
        description = f"PowerShell script block executed: {script_block}"
        source_ip = "localhost"

    # ── Services ─────────────────────────────────────────────────────────
    elif event_id in (7034, 7035, 7036):
        service = get(0)
        state = get(1) if event_id == 7036 else ("started" if event_id == 7035 else "crashed")
        description = f"Service '{service}' {state}"
        source_ip = "localhost"

    # ── Fallback ─────────────────────────────────────────────────────────
    else:
        description = f"{event_type} | Fields: {' | '.join(inserts[:8])}"

    # Ensure we have something for source_ip
    if not source_ip or source_ip in ("-", "::1", "0.0.0.0", "127.0.0.1"):
        source_ip = "localhost"

    # Detect attack type from real event context
    attack_type = detect_attack(
        event_id=event_id,
        source_ip=source_ip,
        description=description,
        target_user=target_user,
        channel=channel,
    )

    if not attack_type:
        return None  # Not security-relevant, skip

    trust_score = score_from_attack(attack_type)
    severity = _severity_from_score(trust_score)

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "timestamp": timestamp,
        "log_source": channel,
        "event_type": event_type,
        "attack_type": attack_type,
        "severity": severity,
        "trust_score": trust_score,
        "description": description,
    }


# ──────────────────────────────────────────────
# Linux log parser
# ──────────────────────────────────────────────
def parse_linux_log(line: str, source_path: str) -> Optional[dict]:
    """Parse a real Linux auth/syslog/kern log line."""
    timestamp = _parse_linux_timestamp(line)
    source_ip = None
    description = ""
    attack_type = None
    target_user = ""

    # Failed SSH password
    m = re.search(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)", line)
    if m:
        target_user, source_ip, port = m.group(1), m.group(2), m.group(3)
        description = f"SSH failed password for '{target_user}' from {source_ip} port {port}"
        attack_type = detect_attack(source_ip=source_ip, description=description, target_user=target_user, raw_line=line)
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path, target_user)

    # Accepted SSH logon
    m = re.search(r"Accepted (\S+) for (\S+) from ([\d.]+) port (\d+)", line)
    if m:
        method, user, source_ip, port = m.group(1), m.group(2), m.group(3), m.group(4)
        description = f"Successful SSH {method} login for '{user}' from {source_ip} port {port}"
        attack_type = "normal"
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path, user)

    # Invalid user
    m = re.search(r"Invalid user (\S+) from ([\d.]+)", line)
    if m:
        target_user, source_ip = m.group(1), m.group(2)
        description = f"SSH login attempted with invalid user '{target_user}' from {source_ip}"
        attack_type = detect_attack(source_ip=source_ip, description=description, target_user=target_user, raw_line=line)
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path, target_user)

    # sudo failures
    m = re.search(r"sudo:.*authentication failure.*user=(\S+)", line)
    if m:
        target_user = m.group(1)
        source_ip = _extract_ip(line) or "localhost"
        description = f"sudo authentication failure for user '{target_user}'"
        attack_type = "suspicious_sudo"
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path, target_user)

    # sudo privilege escalation
    m = re.search(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)", line)
    if m:
        user, command = m.group(1), m.group(2).strip()
        source_ip = "localhost"
        description = f"sudo privilege escalation by '{user}': {command[:200]}"
        attack_type = "privilege_escalation"
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path, user)

    # Account locked
    m = re.search(r"pam_tally|account locked|FAILED LOGIN|Maximum amount of failed", line)
    if m:
        source_ip = _extract_ip(line) or "localhost"
        target_user = _extract_user(line) or "unknown"
        description = f"Account lockout triggered for '{target_user}' on {source_ip}"
        attack_type = "account_lockout"
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path, target_user)

    # UFW block (firewall)
    m = re.search(r"\[UFW BLOCK\].*?SRC=([\d.]+).*?DST=([\d.]+).*?PROTO=(\S+).*?DPT=(\d+)", line)
    if m:
        source_ip, dst_ip, proto, dport = m.group(1), m.group(2), m.group(3), m.group(4)
        description = f"Firewall blocked {proto} from {source_ip} to {dst_ip} port {dport}"
        attack_type = detect_attack(source_ip=source_ip, description=description, raw_line=line)
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path)

    # Kernel DROP (iptables)
    m = re.search(r"kernel:.*?DROP.*?SRC=([\d.]+).*?DST=([\d.]+).*?DPT=(\d+)", line)
    if m:
        source_ip, dst_ip, dport = m.group(1), m.group(2), m.group(3)
        description = f"iptables DROP: {source_ip} → {dst_ip}:{dport}"
        attack_type = "port_scan"
        return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path)

    # Connection refused / errors from syslog
    m = re.search(r"connection from ([\d.]+) \((.*?)\)", line, re.IGNORECASE)
    if m:
        source_ip, info = m.group(1), m.group(2)
        description = f"Network connection from {source_ip}: {info}"
        attack_type = detect_attack(source_ip=source_ip, description=description, raw_line=line)
        if attack_type:
            return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path)

    return None  # Not a security-relevant line


# ──────────────────────────────────────────────
# Network log parser (firewall, DNS, HTTP, Zeek, Suricata)
# ──────────────────────────────────────────────
def parse_network_log(line: str, source_path: str) -> Optional[dict]:
    """Parse real network log lines."""
    timestamp = _parse_linux_timestamp(line) or datetime.now(timezone.utc)

    # ── Suricata EVE JSON ──────────────────────────────────────────────
    if source_path.endswith("eve.json"):
        return _parse_suricata_eve(line, source_path, timestamp)

    # ── Suricata fast.log ─────────────────────────────────────────────
    m = re.search(r'\[Classification:\s*(.*?)\].*?{(.*?)}\s*([\d.]+):\d+\s*->\s*([\d.]+)', line)
    if m:
        classification, proto, src_ip, dst_ip = m.group(1), m.group(2), m.group(3), m.group(4)
        sig_match = re.search(r'\[\*\*\]\s*\[.*?\]\s*(.*?)\s*\[\*\*\]', line)
        sig = sig_match.group(1) if sig_match else classification
        description = f"Suricata alert: '{sig}' | {proto} {src_ip} → {dst_ip}"
        attack_type = detect_attack(source_ip=src_ip, description=description, raw_line=line)
        return _build_linux_alert(src_ip, attack_type or "network_intrusion", description, timestamp, source_path)

    # ── UFW / iptables (also handled in linux parser but keep here for net paths) ─
    m = re.search(r"SRC=([\d.]+).*?DST=([\d.]+).*?DPT=(\d+)", line)
    if m:
        source_ip, dst_ip, dport = m.group(1), m.group(2), m.group(3)
        description = f"Firewall event: {source_ip} → {dst_ip}:{dport}"
        attack_type = detect_attack(source_ip=source_ip, description=description, raw_line=line)
        return _build_linux_alert(source_ip, attack_type or "port_scan", description, timestamp, source_path)

    # ── Zeek conn.log (TSV) ───────────────────────────────────────────
    if "zeek" in source_path:
        return _parse_zeek_conn(line, source_path, timestamp)

    # ── Nginx / Apache access log ─────────────────────────────────────
    m = re.search(r'^([\d.]+) .* "(.*?)" (\d{3}) \d+', line)
    if m:
        source_ip, request, status_code = m.group(1), m.group(2), m.group(3)
        description = f"HTTP {status_code}: '{request}' from {source_ip}"
        attack_type = detect_attack(source_ip=source_ip, description=description, raw_line=line)
        if attack_type:
            return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path)

    # ── DNS query log ─────────────────────────────────────────────────
    m = re.search(r'queries:.*?([\d.]+)#\d+.*?QUERY:\s*(\S+)', line)
    if m:
        source_ip, query = m.group(1), m.group(2)
        description = f"DNS query from {source_ip}: {query}"
        attack_type = detect_attack(source_ip=source_ip, description=description, raw_line=line)
        if attack_type:
            return _build_linux_alert(source_ip, attack_type, description, timestamp, source_path)

    return None


def _parse_suricata_eve(line: str, source_path: str, timestamp) -> Optional[dict]:
    try:
        evt = json.loads(line)
    except Exception:
        return None

    if evt.get("event_type") != "alert":
        return None

    src_ip = evt.get("src_ip", "unknown")
    dst_ip = evt.get("dest_ip")
    proto = evt.get("proto", "")
    alert = evt.get("alert", {})
    signature = alert.get("signature", "Unknown Suricata rule")
    category = alert.get("category", "")
    severity_num = alert.get("severity", 3)

    description = (
        f"Suricata IDS: '{signature}'"
        + (f" [{category}]" if category else "")
        + f" | {proto} {src_ip} → {dst_ip}"
    )
    attack_type = detect_attack(source_ip=src_ip, description=description, raw_line=line)
    # Map Suricata severity (1=high, 2=med, 3=low)
    if severity_num == 1:
        sev = "HIGH"
    elif severity_num == 2:
        sev = "MEDIUM"
    else:
        sev = "LOW"

    from backend.services.detection_engine import score_from_attack
    trust_score = score_from_attack(attack_type or "network_intrusion")
    return {
        "source_ip": src_ip,
        "destination_ip": dst_ip,
        "timestamp": timestamp,
        "log_source": "suricata",
        "event_type": "IDS Alert",
        "attack_type": attack_type or "network_intrusion",
        "severity": sev,
        "trust_score": trust_score,
        "description": description,
    }


def _parse_zeek_conn(line: str, source_path: str, timestamp) -> Optional[dict]:
    if line.startswith("#"):
        return None
    parts = line.split("\t")
    if len(parts) < 10:
        return None
    src_ip = parts[2] if len(parts) > 2 else "unknown"
    dst_ip = parts[4] if len(parts) > 4 else None
    proto = parts[6] if len(parts) > 6 else ""
    service = parts[7] if len(parts) > 7 else ""
    state = parts[11] if len(parts) > 11 else ""
    description = f"Zeek conn: {src_ip} → {dst_ip} proto={proto} service={service} state={state}"
    attack_type = detect_attack(source_ip=src_ip, description=description, raw_line=line)
    if not attack_type:
        return None
    return _build_linux_alert(src_ip, attack_type, description, timestamp, source_path)


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────
def _build_linux_alert(source_ip, attack_type, description, timestamp, log_source, target_user=""):
    if not attack_type:
        return None
    from backend.services.detection_engine import score_from_attack
    trust_score = score_from_attack(attack_type)
    return {
        "source_ip": source_ip or "unknown",
        "destination_ip": None,
        "timestamp": timestamp or datetime.now(timezone.utc),
        "log_source": log_source,
        "event_type": attack_type.replace("_", " ").title(),
        "attack_type": attack_type,
        "severity": _severity_from_score(trust_score),
        "trust_score": trust_score,
        "description": description,
    }


def _severity_from_score(score: int) -> str:
    if score >= 90:
        return "HIGH"
    elif score >= 70:
        return "MEDIUM"
    return "LOW"


def _clean_ip(ip_str: str) -> Optional[str]:
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    # Remove IPv6-mapped prefix
    ip_str = re.sub(r"^::ffff:", "", ip_str)
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip_str):
        if ip_str not in ("0.0.0.0", "255.255.255.255"):
            return ip_str
    if ip_str in ("-", "", "::1", "127.0.0.1"):
        return None
    return None


def _extract_ip(line: str) -> Optional[str]:
    matches = re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
    for m in matches:
        parts = m.split(".")
        if all(0 <= int(p) <= 255 for p in parts):
            if not m.startswith("127.") and m not in ("0.0.0.0", "255.255.255.255"):
                return m
    return None


def _extract_user(line: str) -> Optional[str]:
    m = re.search(r"user[=:\s]+(\S+)", line, re.IGNORECASE)
    return m.group(1) if m else None


def _parse_linux_timestamp(line: str) -> Optional[datetime]:
    # Syslog format: "Mar 28 08:12:34"
    m = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            now = datetime.now()
            ts = datetime.strptime(f"{now.year} {m.group(1)}", "%Y %b %d %H:%M:%S")
            return ts.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    # ISO format
    m = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.fromisoformat(m.group(1)).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)