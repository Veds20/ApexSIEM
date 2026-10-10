from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from uuid import UUID, uuid4


class EventSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class EventOutcome(str, Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"


class EventSourceType(str, Enum):
    WINDOWS_SECURITY = "windows_security"
    WINDOWS_SYSTEM = "windows_system"
    WINDOWS_APPLICATION = "windows_application"
    WINDOWS_POWERSHELL = "windows_powershell"
    WINDOWS_SYSMON = "windows_sysmon"
    LINUX_AUTH = "linux_auth"
    LINUX_SYSLOG = "linux_syslog"
    LINUX_AUDITD = "linux_auditd"
    LINUX_JOURNALD = "linux_journald"
    NETWORK_FIREWALL = "network_firewall"
    NETWORK_DNS = "network_dns"
    NETWORK_DHCP = "network_dhcp"
    NETWORK_IDS = "network_ids"
    NETWORK_PROXY = "network_proxy"
    ENDPOINT_EDR = "endpoint_edr"
    CLOUD_AWS = "cloud_aws"
    CLOUD_AZURE = "cloud_azure"
    CLOUD_GCP = "cloud_gcp"
    APPLICATION = "application"


class NetworkProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    DHCP = "DHCP"
    SSH = "SSH"
    RDP = "RDP"
    SMB = "SMB"
    LDAP = "LDAP"
    KERBEROS = "KERBEROS"
    NTP = "NTP"
    OTHER = "OTHER"


class AuthenticationType(str, Enum):
    PASSWORD = "PASSWORD"
    PUBLIC_KEY = "PUBLIC_KEY"
    KERBEROS = "KERBEROS"
    NTLM = "NTLM"
    CERTIFICATE = "CERTIFICATE"
    MFA = "MFA"
    UNKNOWN = "UNKNOWN"


class LogonType(str, Enum):
    INTERACTIVE = "INTERACTIVE"
    NETWORK = "NETWORK"
    BATCH = "BATCH"
    SERVICE = "SERVICE"
    UNLOCK = "UNLOCK"
    NETWORK_CLEARTEXT = "NETWORK_CLEARTEXT"
    NEW_CREDENTIALS = "NEW_CREDENTIALS"
    REMOTE_INTERACTIVE = "REMOTE_INTERACTIVE"
    CACHED_INTERACTIVE = "CACHED_INTERACTIVE"
    CACHED_REMOTE_INTERACTIVE = "CACHED_REMOTE_INTERACTIVE"
    UNKNOWN = "UNKNOWN"


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class BaseEvent(BaseModel):
    model_config = ConfigDict(use_enum_values=True, extra="allow")

    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(description="Event occurrence time (UTC)")
    ingested_at: datetime = Field(default_factory=datetime.utcnow, description="Ingestion time (UTC)")
    source_type: EventSourceType
    source_name: str = Field(description="Specific source identifier (e.g., 'Security', '/var/log/auth.log', 'AWS CloudTrail')")
    host: Optional[str] = Field(None, description="Hostname or agent ID where event originated")
    event_type: str = Field(description="Specific event identifier (e.g., '4625', 'Failed password', 'ProcessCreate')")
    event_category: Optional[str] = Field(None, description="High-level category (authentication, process, network, etc.)")
    action: Optional[str] = Field(None, description="Action performed (login, create, delete, connect, etc.)")
    outcome: EventOutcome = EventOutcome.UNKNOWN
    severity: EventSeverity = EventSeverity.INFORMATIONAL

    user: Optional[str] = Field(None, description="User/account involved")
    user_domain: Optional[str] = Field(None, description="User domain (for Windows)")
    user_sid: Optional[str] = Field(None, description="User SID (for Windows)")
    target_user: Optional[str] = Field(None, description="Target user (for impersonation, admin actions)")
    target_user_domain: Optional[str] = Field(None, description="Target user domain")
    target_user_sid: Optional[str] = Field(None, description="Target user SID")

    source_ip: Optional[str] = Field(None, description="Source IP address")
    source_port: Optional[int] = Field(None, description="Source port")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    destination_port: Optional[int] = Field(None, description="Destination port")
    protocol: Optional[NetworkProtocol] = Field(None, description="Network protocol")

    process_name: Optional[str] = Field(None, description="Process executable name")
    process_path: Optional[str] = Field(None, description="Full process path")
    process_command_line: Optional[str] = Field(None, description="Full command line")
    process_pid: Optional[int] = Field(None, description="Process ID")
    process_parent_name: Optional[str] = Field(None, description="Parent process name")
    process_parent_path: Optional[str] = Field(None, description="Parent process path")
    process_parent_pid: Optional[int] = Field(None, description="Parent process ID")
    process_user: Optional[str] = Field(None, description="Process owner/user")
    process_integrity_level: Optional[str] = Field(None, description="Process integrity level (Windows)")

    authentication_type: Optional[AuthenticationType] = Field(None, description="Authentication method used")
    logon_type: Optional[LogonType] = Field(None, description="Windows logon type")
    authentication_package: Optional[str] = Field(None, description="Authentication package (e.g., Negotiate, Kerberos)")
    failure_reason: Optional[str] = Field(None, description="Reason for authentication/operation failure")

    dns_query: Optional[str] = Field(None, description="DNS query name")
    dns_query_type: Optional[str] = Field(None, description="DNS query type (A, AAAA, MX, etc.)")
    dns_response_code: Optional[str] = Field(None, description="DNS response code")
    dns_answers: Optional[List[str]] = Field(None, description="DNS answer records")

    file_path: Optional[str] = Field(None, description="File path involved")
    file_hash_md5: Optional[str] = Field(None, description="File MD5 hash")
    file_hash_sha1: Optional[str] = Field(None, description="File SHA1 hash")
    file_hash_sha256: Optional[str] = Field(None, description="File SHA256 hash")
    file_size: Optional[int] = Field(None, description="File size in bytes")

    registry_key: Optional[str] = Field(None, description="Registry key path")
    registry_value: Optional[str] = Field(None, description="Registry value name")
    registry_data: Optional[str] = Field(None, description="Registry value data")

    raw_data: Dict[str, Any] = Field(default_factory=dict, description="Original raw event data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Extensible metadata")


class NormalizedEvent(BaseEvent):
    pass


class RawEvent(BaseModel):
    model_config = ConfigDict(extra="allow")

    event_id: UUID = Field(default_factory=uuid4)
    ingested_at: datetime = Field(default_factory=datetime.utcnow)
    source_type: EventSourceType
    source_name: str
    host: Optional[str] = None
    raw_content: str
    parsed_data: Optional[Dict[str, Any]] = None
    parse_errors: Optional[List[str]] = None
    collector_id: Optional[str] = None


class EventBatch(BaseModel):
    events: List[RawEvent]
    batch_id: UUID = Field(default_factory=uuid4)
    source_type: EventSourceType
    collector_id: Optional[str] = None
    received_at: datetime = Field(default_factory=datetime.utcnow)
