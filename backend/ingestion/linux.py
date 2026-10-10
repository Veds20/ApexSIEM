import asyncio
import logging
import re
from datetime import datetime, timezone
from ipaddress import ip_address
from typing import AsyncIterator, Optional

from ..schemas.normalized import RawEvent, EventBatch, EventSourceType, NormalizedEvent, EventSeverity
from .base import EventCollector, EventParser
from ..services.detection_engine import detect_attack, score_from_attack

logger = logging.getLogger(__name__)

LINUX_LOG_PATHS = {
    "auth": ["/var/log/auth.log", "/var/log/secure"],
    "syslog": ["/var/log/syslog", "/var/log/messages"],
    "kern": ["/var/log/kern.log"],
    "audit": ["/var/log/audit/audit.log"],
}
SSH_FAILED_PATTERN = re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")
SSH_ACCEPTED_PATTERN = re.compile(r"Accepted (\S+) for (\S+) from ([\d.]+) port (\d+)")
SSH_INVALID_USER = re.compile(r"Invalid user (\S+) from ([\d.]+)")
SUDO_FAILURE = re.compile(r"sudo:.*authentication failure.*user=(\S+)")
SUDO_COMMAND = re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")
ACCOUNT_LOCKED = re.compile(r"pam_tally|account locked|FAILED LOGIN|Maximum amount of failed", re.IGNORECASE)
UFW_BLOCK = re.compile(r"\[UFW BLOCK\].*?SRC=([\d.]+).*?DST=([\d.]+).*?PROTO=(\S+).*?DPT=(\d+)")
KERNEL_DROP = re.compile(r"kernel:.*?DROP.*?SRC=([\d.]+).*?DST=([\d.]+).*?DPT=(\d+)")
CONNECTION_FROM = re.compile(r"connection from ([\d.]+) \((.*?)\)", re.IGNORECASE)
SYSTEMD_SERVICE = re.compile(r"systemd\[.*\]: (Started|Stopped|Failed) (.+)")
CRON_JOB = re.compile(r"CRON\[.*\]: \(([^)]+)\) CMD \((.+)\)")


def _parse_linux_timestamp(line: str) -> datetime:
    month_day = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if month_day:
        try:
            current_year = datetime.now(timezone.utc).year
            naive = datetime.strptime(f"{current_year} {month_day.group(1)}", "%Y %b %d %H:%M:%S")
            return naive.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    iso_timestamp = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", line)
    if iso_timestamp:
        try:
            value = iso_timestamp.group(1).replace("Z", "+00:00")
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _clean_ip(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        parsed = ip_address(value.strip())
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return None
        return str(parsed)
    except ValueError:
        return None


def _extract_ip(line: str) -> Optional[str]:
    for candidate in re.findall(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line):
        cleaned = _clean_ip(candidate)
        if cleaned:
            return cleaned
    return None


def _extract_user(line: str) -> Optional[str]:
    match = re.search(r"user[=:\s]+(\S+)", line, re.IGNORECASE)
    return match.group(1) if match else None


def _severity(score: int) -> EventSeverity:
    if score >= 90:
        return EventSeverity.HIGH
    if score >= 70:
        return EventSeverity.MEDIUM
    if score >= 40:
        return EventSeverity.LOW
    return EventSeverity.INFORMATIONAL


def parse_linux_log_line(line: str, source_path: str) -> Optional[NormalizedEvent]:
    timestamp = _parse_linux_timestamp(line)
    source_ip = None
    target_user = None
    attack_type = None
    description = ""
    event_type = "Linux log event"

    match = SSH_FAILED_PATTERN.search(line)
    if match:
        target_user, source_ip, port = match.group(1), _clean_ip(match.group(2)), match.group(3)
        event_type = "SSH authentication failure"
        description = f"SSH failed password for '{target_user}'"
        if source_ip:
            description += f" from {source_ip}"
        description += f" port {port}"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, target_user=target_user, raw_line=line)

    if attack_type is None:
        match = SSH_INVALID_USER.search(line)
        if match:
            target_user, source_ip = match.group(1), _clean_ip(match.group(2))
            event_type = "SSH invalid-user attempt"
            description = f"SSH login attempted with invalid user '{target_user}'"
            if source_ip:
                description += f" from {source_ip}"
            attack_type = detect_attack(source_ip=source_ip or "", description=description, target_user=target_user, raw_line=line)

    if attack_type is None:
        match = SUDO_FAILURE.search(line)
        if match:
            target_user = match.group(1)
            source_ip = _extract_ip(line)
            event_type = "Sudo authentication failure"
            description = f"sudo authentication failure for user '{target_user}'"
            attack_type = "suspicious_sudo"

    if attack_type is None:
        match = SUDO_COMMAND.search(line)
        if match:
            target_user, command = match.group(1), match.group(2).strip()
            event_type = "Sudo command"
            description = f"sudo command by '{target_user}': {command[:200]}"
            attack_type = "privilege_escalation"

    if attack_type is None:
        match = ACCOUNT_LOCKED.search(line)
        if match:
            source_ip = _extract_ip(line)
            target_user = _extract_user(line)
            event_type = "Account lockout"
            description = "Account lockout signal found in authentication log"
            attack_type = "account_lockout"

    if attack_type is None:
        match = UFW_BLOCK.search(line)
        if match:
            source_ip, destination_ip, protocol, destination_port = match.groups()
            source_ip = _clean_ip(source_ip)
            event_type = "UFW firewall block"
            description = f"Firewall blocked {protocol} from {source_ip or 'unrecorded source'} to {destination_ip}:{destination_port}"
            attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line)

    if attack_type is None:
        match = KERNEL_DROP.search(line)
        if match:
            source_ip, destination_ip, destination_port = match.groups()
            source_ip = _clean_ip(source_ip)
            event_type = "Kernel firewall drop"
            description = f"iptables DROP: {source_ip or 'unrecorded source'} to {destination_ip}:{destination_port}"
            attack_type = "port_scan"

    if attack_type is None:
        match = CONNECTION_FROM.search(line)
        if match:
            source_ip = _clean_ip(match.group(1))
            event_type = "Incoming network connection"
            description = f"Network connection from {source_ip or 'unrecorded source'}: {match.group(2)}"
            attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line)

    if attack_type is None:
        match = SYSTEMD_SERVICE.search(line)
        if match and match.group(1) == "Failed":
            event_type = "Systemd service failure"
            description = f"Systemd service failed: {match.group(2)}"
            attack_type = "service_anomaly"

    if not attack_type:
        return None

    score = score_from_attack(attack_type)
    path_lower = source_path.lower()
    source_type = EventSourceType.LINUX_AUDITD if "audit" in path_lower else EventSourceType.LINUX_SYSLOG if any(key in path_lower for key in ("syslog", "messages", "kern")) else EventSourceType.LINUX_AUTH
    return NormalizedEvent(
        timestamp=timestamp,
        source_type=source_type,
        source_name=source_path,
        host=None,
        event_type=event_type,
        attack_type=attack_type,
        severity=_severity(score),
        source_ip=source_ip,
        user=target_user,
        description=description,
        raw_data={"raw_line": line},
        metadata={"trust_score": score},
    )


class LinuxEventCollector(EventCollector):
    def __init__(self, collector_id: str = "linux-collector", log_paths: dict = None):
        super().__init__(collector_id, EventSourceType.LINUX_AUTH)
        self.log_paths = log_paths or LINUX_LOG_PATHS
        self._file_handles = {}
        self._positions = {}

    async def start(self):
        self._running = True
        for paths in self.log_paths.values():
            for path in paths:
                if path in self._file_handles:
                    continue
                handle = None
                try:
                    handle = open(path, "r", encoding="utf-8", errors="replace")
                    handle.seek(0, 2)
                    self._file_handles[path] = handle
                    self._positions[path] = handle.tell()
                    logger.info("Watching Linux log: %s", path)
                except OSError as exc:
                    logger.debug("Cannot open Linux log %s: %s", path, exc)
                    if handle:
                        handle.close()
        if not self._file_handles:
            logger.warning("No configured Linux log files are readable.")
        else:
            logger.info("Linux collector ready for %d files.", len(self._file_handles))

    async def stop(self):
        self._running = False
        for handle in self._file_handles.values():
            try:
                handle.close()
            except OSError:
                pass
        self._file_handles.clear()
        self._positions.clear()

    async def collect(self) -> AsyncIterator[EventBatch]:
        if not self._file_handles:
            return
        while self._running:
            for path, handle in list(self._file_handles.items()):
                try:
                    handle.seek(self._positions.get(path, 0))
                    lines = handle.readlines()
                    self._positions[path] = handle.tell()
                    for line in lines:
                        raw_line = line.strip()
                        if not raw_line:
                            continue
                        source_type = EventSourceType.LINUX_AUDITD if "audit" in path.lower() else EventSourceType.LINUX_SYSLOG if any(key in path.lower() for key in ("syslog", "messages", "kern")) else EventSourceType.LINUX_AUTH
                        yield EventBatch(
                            events=[RawEvent(source_type=source_type, source_name=path, host=None, raw_content=raw_line, collector_id=self.collector_id)],
                            source_type=source_type,
                            collector_id=self.collector_id,
                        )
                except (OSError, ValueError) as exc:
                    logger.warning("Read failed for Linux log %s: %s", path, exc)
            await asyncio.sleep(0.5)


class LinuxEventParser(EventParser):
    def can_parse(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type in {
            EventSourceType.LINUX_AUTH,
            EventSourceType.LINUX_SYSLOG,
            EventSourceType.LINUX_AUDITD,
            EventSourceType.LINUX_JOURNALD,
        }

    def parse(self, raw_event: RawEvent) -> Optional[NormalizedEvent]:
        return parse_linux_log_line(raw_event.raw_content, raw_event.source_name or "unknown")
