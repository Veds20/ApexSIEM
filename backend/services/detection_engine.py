"""
Real Detection Engine
=====================
Derives attack type from REAL event fields using:
  - Windows Event ID rules
  - Pattern recognition on real log fields
  - Threshold / rate-based logic (brute force, port scan)
  - NO fabrication, NO random assignment

All description strings passed in are derived from actual log content
by log_parser.py before reaching this module.
"""

import re
import time
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Optional

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
# In-memory rate trackers for threshold-based detection
# We track per-source-IP failure counts within a sliding window
# ─────────────────────────────────────────────────────────────────────────────
_WINDOW_SECONDS = 60          # sliding window
_BRUTE_FORCE_THRESHOLD = 5    # failed logins in window → brute_force
_PORT_SCAN_THRESHOLD = 15     # distinct destination ports in window → port_scan

# {source_ip: [(timestamp, event_type), ...]}
_event_tracker: dict[str, list] = defaultdict(list)


def _track(source_ip: str, event_type: str):
    now = time.time()
    _event_tracker[source_ip].append((now, event_type))
    # Prune old entries
    cutoff = now - _WINDOW_SECONDS
    _event_tracker[source_ip] = [
        (ts, et) for ts, et in _event_tracker[source_ip] if ts > cutoff
    ]


def _count_recent(source_ip: str, event_type: str) -> int:
    now = time.time()
    cutoff = now - _WINDOW_SECONDS
    return sum(
        1 for ts, et in _event_tracker.get(source_ip, [])
        if ts > cutoff and et == event_type
    )


# ─────────────────────────────────────────────────────────────────────────────
# Trust score table
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_TRUST_SCORES = {
    "brute_force": 90,
    "brute_force_rdp": 92,
    "brute_force_ssh": 91,
    "malware": 95,
    "port_scan": 72,
    "privilege_escalation": 93,
    "suspicious_sudo": 78,
    "failed_login": 65,
    "account_lockout": 85,
    "rdp_attack": 88,
    "ssh_attack": 87,
    "log_cleared": 98,
    "audit_policy_changed": 88,
    "scheduled_task_created": 80,
    "new_user_created": 82,
    "user_added_to_group": 79,
    "kerberos_failure": 83,
    "kerberos_brute_force": 92,
    "ntlm_failure": 75,
    "service_anomaly": 70,
    "powershell_suspicious": 90,
    "network_intrusion": 85,
    "dns_suspicious": 72,
    "http_attack": 80,
    "firewall_block": 68,
    "credential_stuffing": 88,
    "lateral_movement": 91,
    "normal": 10,
    "unknown": 30,
}


def score_from_attack(attack_type: str) -> int:
    return ATTACK_TRUST_SCORES.get(attack_type, 50)


# ─────────────────────────────────────────────────────────────────────────────
# Main detection function
# ─────────────────────────────────────────────────────────────────────────────
def detect_attack(
    event_id: int = 0,
    source_ip: str = "",
    description: str = "",
    target_user: str = "",
    channel: str = "",
    raw_line: str = "",
) -> Optional[str]:
    """
    Returns an attack_type string or None (not security-relevant).
    Decision is based on REAL event fields only.
    """
    desc_lower = description.lower()
    raw_lower = raw_line.lower()
    combined = desc_lower + " " + raw_lower

    # ── Windows Event ID rules ────────────────────────────────────────────
    if event_id:
        result = _detect_by_event_id(event_id, source_ip, description, target_user, combined)
        if result is not None:
            return result

    # ── Pattern-based detection on description / raw line ─────────────────
    return _detect_by_pattern(source_ip, combined, target_user)


def _detect_by_event_id(event_id, source_ip, description, target_user, combined) -> Optional[str]:
    """Hard rules based on Windows Event IDs."""

    # Log cleared — always HIGH priority
    if event_id == 1102:
        return "log_cleared"
    if event_id == 1104:
        return "log_cleared"

    # Audit policy changed
    if event_id == 4719:
        return "audit_policy_changed"

    # Scheduled task — persistence mechanism
    if event_id in (4698, 4702):
        return "scheduled_task_created"

    # New user account
    if event_id == 4720:
        return "new_user_created"

    # User added to privileged group
    if event_id in (4728, 4732, 4756):
        return "user_added_to_group"

    # Account lockout
    if event_id == 4740:
        return "account_lockout"

    # Special privileges
    if event_id == 4672:
        # Only flag if the user is not a known service account
        if target_user and not target_user.endswith("$") and target_user.lower() not in (
            "system", "local service", "network service"
        ):
            return "privilege_escalation"
        return None  # Normal service logon — not interesting

    # Failed logon
    if event_id == 4625:
        _track(source_ip, "failed_login")
        fail_count = _count_recent(source_ip, "failed_login")
        if fail_count >= _BRUTE_FORCE_THRESHOLD:
            # Determine if RDP (logon type 10) or SSH
            if "remoteinteractive" in combined or "3389" in combined:
                return "brute_force_rdp"
            if "ssh" in combined or "22" in combined:
                return "brute_force_ssh"
            return "brute_force"
        return "failed_login"

    # Explicit credentials — could be lateral movement
    if event_id == 4648:
        if source_ip and source_ip not in ("localhost", "::1"):
            return "lateral_movement"
        return None

    # Process creation — flag suspicious processes
    if event_id == 4688:
        return _detect_suspicious_process(combined)

    # Kerberos failures
    if event_id in (4768, 4771):
        _track(source_ip, "kerberos_failure")
        if _count_recent(source_ip, "kerberos_failure") >= _BRUTE_FORCE_THRESHOLD:
            return "kerberos_brute_force"
        if "0x6" in combined or "0x18" in combined or "0x24" in combined:
            # Bad password / pre-auth failure
            return "kerberos_failure"
        return None

    # NTLM failures
    if event_id == 4776:
        if "0xc000006a" in combined or "0xc0000064" in combined:
            _track(source_ip, "ntlm_failure")
            if _count_recent(source_ip, "ntlm_failure") >= _BRUTE_FORCE_THRESHOLD:
                return "credential_stuffing"
            return "ntlm_failure"
        return None

    # Successful logon — mostly not security relevant unless certain types
    if event_id == 4624:
        if "networkcleartext" in combined:
            return "failed_login"  # Cleartext credential logon is suspicious
        return None  # Normal success — skip

    # PowerShell script block
    if event_id == 4104:
        return _detect_suspicious_powershell(combined)

    # Service anomalies
    if event_id == 7034:
        return "service_anomaly"

    return None  # Other events — use pattern detection


def _detect_suspicious_process(combined: str) -> Optional[str]:
    """Detect malicious process creation from real command line data."""
    # Suspicious process names and patterns from real threat intel
    malware_indicators = [
        r"mimikatz", r"meterpreter", r"cobalt.?strike", r"invoke-?mimikatz",
        r"bloodhound", r"sharphound", r"rubeus", r"kerbrute",
        r"powersploit", r"empire", r"metasploit",
        r"netcat|ncat|nc\.exe",
    ]
    for pattern in malware_indicators:
        if re.search(pattern, combined):
            return "malware"

    # Suspicious PowerShell patterns
    if re.search(r"powershell.*(-enc|-encodedcommand|-nop|-noprofile|-bypass|-exec bypass|iex|invoke-expression|downloadstring|webclient)", combined):
        return "powershell_suspicious"

    # Lateral movement tools
    if re.search(r"(psexec|wmic.*process|schtasks.*\/create|at\.exe|reg\.exe.*add)", combined):
        return "lateral_movement"

    # Privilege escalation patterns
    if re.search(r"(whoami|net localgroup administrators|net user.*\/add|runas)", combined):
        return "privilege_escalation"

    return None  # Normal process — not interesting


def _detect_suspicious_powershell(combined: str) -> Optional[str]:
    """Detect malicious PowerShell from script block content."""
    if re.search(r"(-enc|-encodedcommand|invoke-expression|iex\(|downloadstring|webclient|bypass|amsi|reflection\.assembly)", combined):
        return "powershell_suspicious"
    if re.search(r"(mimikatz|sekurlsa|kerberoast|pass.?the.?hash)", combined):
        return "malware"
    return None


def _detect_by_pattern(source_ip: str, combined: str, target_user: str) -> Optional[str]:
    """Pattern-based detection for Linux / network logs."""

    # SSH brute force
    if re.search(r"failed password|authentication failure|invalid user", combined):
        _track(source_ip, "failed_login")
        count = _count_recent(source_ip, "failed_login")
        if count >= _BRUTE_FORCE_THRESHOLD:
            return "brute_force_ssh"
        return "failed_login"

    # Successful auth
    if re.search(r"accepted (password|publickey)|successful (logon|login)", combined):
        return "normal"

    # sudo failures
    if re.search(r"sudo.*authentication failure", combined):
        return "suspicious_sudo"

    # Privilege escalation via sudo
    if re.search(r"sudo.*command=|sudo:.*->", combined):
        return "privilege_escalation"

    # Account lockout
    if re.search(r"pam_tally|account locked|maximum.*failed|lockout", combined):
        return "account_lockout"

    # Firewall blocks / port scanning
    if re.search(r"\[ufw block\]|iptables.*drop|firewall.*block|denied", combined):
        if source_ip:
            _track(source_ip, "firewall_block")
            if _count_recent(source_ip, "firewall_block") >= _PORT_SCAN_THRESHOLD:
                return "port_scan"
        return "firewall_block"

    # Suricata / IDS alerts
    if re.search(r"suricata|snort|ids.*alert|alert.*signature", combined):
        # Classify by Suricata category keywords
        if re.search(r"malware|trojan|ransomware|c2|command.?and.?control", combined):
            return "malware"
        if re.search(r"scan|probe|recon", combined):
            return "port_scan"
        if re.search(r"brute|password|credential", combined):
            return "brute_force"
        return "network_intrusion"

    # HTTP attack patterns
    if re.search(r"(sqlmap|havij|nikto|dirb|gobuster|wfuzz)", combined):
        return "http_attack"
    if re.search(r'(union.*select|<script>|../../../|cmd=|exec\(|eval\()', combined):
        return "http_attack"

    # DNS suspicious
    if re.search(r"(dns.*refused|nxdomain.*repeated|dns.*tunnel|dnscat)", combined):
        return "dns_suspicious"

    # Malware keywords in raw logs
    if re.search(r"(malware|ransomware|trojan|c2|command.and.control|beacon)", combined):
        return "malware"

    # Zeek connection anomalies
    if re.search(r"(s0|rex|rstos0|rstrh|sh|srh)", combined) and "zeek" in combined:
        return "network_intrusion"

    return None  # Not security-relevant