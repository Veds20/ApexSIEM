from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class MitreTactic(str, Enum):
    RECONNAISSANCE = "TA0043"
    RESOURCE_DEVELOPMENT = "TA0042"
    INITIAL_ACCESS = "TA0001"
    EXECUTION = "TA0002"
    PERSISTENCE = "TA0003"
    PRIVILEGE_ESCALATION = "TA0004"
    DEFENSE_EVASION = "TA0005"
    CREDENTIAL_ACCESS = "TA0006"
    DISCOVERY = "TA0007"
    LATERAL_MOVEMENT = "TA0008"
    COLLECTION = "TA0009"
    COMMAND_AND_CONTROL = "TA0011"
    EXFILTRATION = "TA0010"
    IMPACT = "TA0040"


class MitreTechnique(BaseModel):
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID (e.g., T1059)")
    name: str = Field(..., description="Technique name")
    tactic: MitreTactic = Field(..., description="Primary tactic")
    sub_techniques: List[str] = Field(default_factory=list, description="Sub-technique IDs")
    description: str = Field(default="", description="Technique description")
    detection: str = Field(default="", description="Detection guidance")
    data_sources: List[str] = Field(default_factory=list, description="Data sources for detection")


MITRE_TECHNIQUE_MAPPING = {
    "brute_force": MitreTechnique(
        technique_id="T1110", name="Brute Force", tactic=MitreTactic.CREDENTIAL_ACCESS,
        sub_techniques=["T1110.001", "T1110.002", "T1110.003", "T1110.004"],
        description="Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
        detection="Monitor for failed authentication attempts, especially from the same source IP or targeting the same account.",
        data_sources=["Authentication logs", "Active Directory", "SIEM"]),
    "brute_force_rdp": MitreTechnique(
        technique_id="T1110.001", name="Password Guessing", tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Adversaries may attempt to guess passwords for RDP access.",
        detection="Monitor for RDP logon failures (Event ID 4625 with logon type 10).",
        data_sources=["Windows Security Event Log", "RDP logs"]),
    "brute_force_ssh": MitreTechnique(
        technique_id="T1110.001", name="Password Guessing", tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Adversaries may attempt to guess passwords for SSH access.",
        detection="Monitor for SSH authentication failures in auth.log.",
        data_sources=["Linux auth.log", "SSH logs"]),
    "kerberos_brute_force": MitreTechnique(
        technique_id="T1558", name="Steal or Forge Kerberos Tickets", tactic=MitreTactic.CREDENTIAL_ACCESS,
        sub_techniques=["T1558.001", "T1558.002", "T1558.003"],
        description="Adversaries may attempt to brute force Kerberos pre-authentication.",
        detection="Monitor for Kerberos pre-authentication failures (Event ID 4771).",
        data_sources=["Windows Security Event Log", "Kerberos logs"]),
    "credential_stuffing": MitreTechnique(
        technique_id="T1110.004", name="Credential Stuffing", tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Adversaries use credentials from data breaches to attempt authentication.",
        detection="Monitor for authentication failures with known breached credentials.",
        data_sources=["Authentication logs", "Threat intelligence feeds"]),
    "privilege_escalation": MitreTechnique(
        technique_id="T1068", name="Exploitation for Privilege Escalation", tactic=MitreTactic.PRIVILEGE_ESCALATION,
        description="Adversaries exploit vulnerabilities to escalate privileges.",
        detection="Monitor for privilege escalation attempts, service installations, and registry modifications.",
        data_sources=["Windows Security Event Log", "Sysmon", "Registry"]),
    "suspicious_sudo": MitreTechnique(
        technique_id="T1548.003", name="Sudo and Sudo Caching", tactic=MitreTactic.PRIVILEGE_ESCALATION,
        description="Adversaries may abuse sudo configurations to escalate privileges.",
        detection="Monitor sudo logs for authentication failures and unusual command executions.",
        data_sources=["Linux auth.log", "sudo logs", "auditd"]),
    "account_lockout": MitreTechnique(
        technique_id="T1606", name="Forge Web Credentials", tactic=MitreTactic.CREDENTIAL_ACCESS,
        description="Account lockout events may indicate brute force or credential stuffing.",
        detection="Monitor for account lockout events (Event ID 4740).",
        data_sources=["Windows Security Event Log", "Active Directory"]),
    "rdp_attack": MitreTechnique(
        technique_id="T1021.001", name="Remote Desktop Protocol", tactic=MitreTactic.LATERAL_MOVEMENT,
        description="Adversaries may use RDP to move laterally.",
        detection="Monitor for RDP connections, especially from unusual sources or with failed attempts followed by success.",
        data_sources=["Windows Security Event Log", "RDP logs", "Network logs"]),
    "lateral_movement": MitreTechnique(
        technique_id="T1021", name="Remote Services", tactic=MitreTactic.LATERAL_MOVEMENT,
        sub_techniques=["T1021.001", "T1021.002", "T1021.003", "T1021.004", "T1021.005", "T1021.006"],
        description="Adversaries use remote services to move laterally.",
        detection="Monitor for logons using explicit credentials (Event ID 4648) from remote IPs.",
        data_sources=["Windows Security Event Log", "Network logs", "Sysmon"]),
    "log_cleared": MitreTechnique(
        technique_id="T1070.001", name="Clear Windows Event Logs", tactic=MitreTactic.DEFENSE_EVASION,
        description="Adversaries may clear event logs to hide activity.",
        detection="Monitor for Event ID 1102 (audit log cleared).",
        data_sources=["Windows Security Event Log"]),
    "audit_policy_changed": MitreTechnique(
        technique_id="T1562.002", name="Disable Windows Event Logging", tactic=MitreTactic.DEFENSE_EVASION,
        description="Adversaries may modify audit policies to evade detection.",
        detection="Monitor for Event ID 4719 (audit policy changed).",
        data_sources=["Windows Security Event Log"]),
    "new_user_created": MitreTechnique(
        technique_id="T1136.001", name="Create Account: Local Account", tactic=MitreTactic.PERSISTENCE,
        description="Adversaries may create accounts for persistence.",
        detection="Monitor for Event ID 4720 (user account created).",
        data_sources=["Windows Security Event Log", "Active Directory"]),
    "scheduled_task_created": MitreTechnique(
        technique_id="T1053.005", name="Scheduled Task/Job: Scheduled Task", tactic=MitreTactic.PERSISTENCE,
        description="Adversaries may create scheduled tasks for persistence.",
        detection="Monitor for Event ID 4698/4702 (scheduled task created/updated).",
        data_sources=["Windows Security Event Log", "Task Scheduler logs"]),
    "powershell_suspicious": MitreTechnique(
        technique_id="T1059.001", name="PowerShell", tactic=MitreTactic.EXECUTION,
        sub_techniques=["T1059.001", "T1059.003", "T1059.004", "T1059.005", "T1059.006", "T1059.007", "T1059.008"],
        description="Adversaries use PowerShell for execution.",
        detection="Monitor PowerShell script block logging (Event ID 4104) for obfuscated commands, encoded commands, and known malicious patterns.",
        data_sources=["Windows PowerShell Operational Log", "Sysmon Event ID 1", "ETW"]),
    "malware": MitreTechnique(
        technique_id="T1204", name="User Execution", tactic=MitreTactic.EXECUTION,
        sub_techniques=["T1204.001", "T1204.002"],
        description="Adversaries use malware tools for execution.",
        detection="Monitor process creation for known malware signatures (Mimikatz, Cobalt Strike, etc.).",
        data_sources=["Sysmon Event ID 1", "EDR", "Antivirus"]),
    "port_scan": MitreTechnique(
        technique_id="T1595.001", name="Active Scanning: Scanning IP Blocks", tactic=MitreTactic.RECONNAISSANCE,
        description="Adversaries scan for open ports.",
        detection="Monitor firewall logs for repeated connection attempts to multiple ports from same source.",
        data_sources=["Firewall logs", "IDS/IPS", "Network logs"]),
    "network_intrusion": MitreTechnique(
        technique_id="T1190", name="Exploit Public-Facing Application", tactic=MitreTactic.INITIAL_ACCESS,
        description="Network intrusion detected by IDS/IPS.",
        detection="Monitor Suricata/Zeek alerts for exploit attempts.",
        data_sources=["Suricata", "Zeek", "Network logs"]),
    "http_attack": MitreTechnique(
        technique_id="T1190", name="Exploit Public-Facing Application", tactic=MitreTactic.INITIAL_ACCESS,
        description="Web application attacks detected.",
        detection="Monitor web server logs for SQL injection, XSS, path traversal, and scanner tools.",
        data_sources=["Web server logs", "WAF", "Proxy logs"]),
    "dns_suspicious": MitreTechnique(
        technique_id="T1071.004", name="Application Layer Protocol: DNS", tactic=MitreTactic.COMMAND_AND_CONTROL,
        description="Suspicious DNS activity indicating C2 or data exfiltration.",
        detection="Monitor for DNS tunneling, high entropy domains, and DGA patterns.",
        data_sources=["DNS logs", "Zeek", "Passive DNS"]),
    "firewall_block": MitreTechnique(
        technique_id="T1595", name="Active Scanning", tactic=MitreTactic.RECONNAISSANCE,
        description="Firewall blocked connection attempt.",
        detection="Monitor firewall block events for patterns.",
        data_sources=["Firewall logs", "Network logs"]),
    "normal": MitreTechnique(
        technique_id="", name="Normal Activity", tactic=MitreTactic.RECONNAISSANCE,
        description="Benign activity.", detection="N/A", data_sources=[]),
}


def get_mitre_technique(attack_type: str) -> Optional[MitreTechnique]:
    """Get MITRE ATT&CK technique for an attack type."""
    return MITRE_TECHNIQUE_MAPPING.get(attack_type.lower())


def get_all_techniques() -> Dict[str, MitreTechnique]:
    """Get all mapped MITRE techniques."""
    return MITRE_TECHNIQUE_MAPPING.copy()


def get_techniques_by_tactic(tactic: str) -> List[MitreTechnique]:
    """Get all techniques for a given tactic."""
    return [technique for technique in MITRE_TECHNIQUE_MAPPING.values() if technique.tactic.value == tactic]
