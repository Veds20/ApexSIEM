import asyncio
import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator, Optional
from ipaddress import ip_address

from ..schemas.normalized import RawEvent, EventBatch, EventSourceType, NormalizedEvent, EventSeverity, LogonType
from .base import EventCollector, EventParser
from ..services.detection_engine import detect_attack, score_from_attack

logger = logging.getLogger(__name__)

CHANNELS = {
    "Security": EventSourceType.WINDOWS_SECURITY,
    "System": EventSourceType.WINDOWS_SYSTEM,
    "Application": EventSourceType.WINDOWS_APPLICATION,
    "Microsoft-Windows-PowerShell/Operational": EventSourceType.WINDOWS_POWERSHELL,
}
EVENT_IDS = {
    4624, 4625, 4648, 4656, 4663, 4672, 4688, 4689, 4690, 4697, 4698, 4699,
    4700, 4701, 4702, 4719, 4720, 4722, 4724, 4725, 4726, 4728, 4732, 4738,
    4740, 4756, 4768, 4769, 4771, 4776, 4798, 4799, 1100, 1102, 1104, 4104,
    7034, 7035, 7036, 5140, 5145, 5156, 5158, 5159, 5160, 5161, 5162,
}
DESCRIPTIONS = {
    4624: "Successful logon", 4625: "Failed logon attempt",
    4648: "Logon using explicit credentials", 4656: "Object handle requested",
    4663: "Object access attempt", 4672: "Special privileges assigned to new logon",
    4688: "New process created", 4689: "Process exited", 4690: "Process terminated",
    4697: "Service installed", 4698: "Scheduled task created", 4699: "Scheduled task deleted",
    4700: "Scheduled task enabled", 4701: "Scheduled task disabled", 4702: "Scheduled task updated",
    4719: "System audit policy changed", 4720: "User account created",
    4722: "User account enabled", 4724: "Password reset attempt", 4725: "User account disabled",
    4726: "User account deleted", 4728: "Member added to global group",
    4732: "Member added to local group", 4738: "User account changed",
    4740: "User account locked out", 4756: "Member added to universal group",
    4768: "Kerberos TGT requested", 4769: "Kerberos service ticket requested",
    4771: "Kerberos pre-authentication failed", 4776: "NTLM authentication attempt",
    4798: "User local group membership enumerated", 4799: "Local group membership enumerated",
    1100: "Event logging service shut down", 1102: "Audit log cleared",
    1104: "Security log is full", 4104: "PowerShell script block logged",
    7034: "Service crashed unexpectedly", 7035: "Service control sent", 7036: "Service state changed",
    5140: "Network share object accessed", 5145: "Network share object checked",
    5156: "Filtering platform connection allowed", 5158: "Filtering platform binding allowed",
    5159: "Filtering platform binding blocked", 5160: "Filtering platform binding blocked",
    5161: "Filtering platform drop", 5162: "Filtering platform drop (IPsec)",
}
LOGON_TYPES = {
    "2": LogonType.INTERACTIVE, "3": LogonType.NETWORK, "4": LogonType.BATCH,
    "5": LogonType.SERVICE, "7": LogonType.UNLOCK, "8": LogonType.NETWORK_CLEARTEXT,
    "9": LogonType.NEW_CREDENTIALS, "10": LogonType.REMOTE_INTERACTIVE,
    "11": LogonType.CACHED_INTERACTIVE, "12": LogonType.UNKNOWN,
}


def clean_ip(value: Optional[str]) -> Optional[str]:
    if not value or value.strip() in {"-", "0.0.0.0", "::", "::1", "127.0.0.1"}:
        return None
    candidate = re.sub(r"^::ffff:", "", value.strip(), flags=re.IGNORECASE)
    try:
        parsed = ip_address(candidate)
        if parsed.is_loopback or parsed.is_unspecified or parsed.is_multicast:
            return None
        return str(parsed)
    except ValueError:
        return None


def parse_windows_event(event_id: int, inserts: list, channel: str, raw_log: str,
                        timestamp: Optional[datetime] = None) -> Optional[NormalizedEvent]:
    fields = [str(value) for value in (inserts or [])]

    def get(index, default=""):
        return fields[index] if index < len(fields) else default

    target_user = subject_user = process_name = parent_process = command_line = ""
    source_ip = None
    logon_type = None
    failure_reason = None
    event_type = DESCRIPTIONS.get(event_id, f"EventID {event_id}")

    if event_id == 4625:
        target_user, subject_user = get(5), get(1)
        logon_type = LOGON_TYPES.get(get(10), LogonType.UNKNOWN)
        source_ip = clean_ip(get(19))
        failure_reason = get(9)
        description = f"Failed {logon_type.value} logon for account '{target_user}'"
        if source_ip:
            description += f" from {source_ip}"
        if failure_reason and failure_reason != "%%2313":
            description += f". Reason: {failure_reason}"
    elif event_id == 4624:
        target_user = get(5)
        logon_type = LOGON_TYPES.get(get(8), LogonType.UNKNOWN)
        source_ip = clean_ip(get(18))
        description = f"Successful {logon_type.value} logon for account '{target_user}'"
        if source_ip:
            description += f" from {source_ip}"
    elif event_id == 4648:
        subject_user, target_user = get(1), get(5)
        source_ip = clean_ip(get(12))
        description = f"Explicit credentials used by '{subject_user}' to authenticate as '{target_user}'"
        if get(8):
            description += f" to server '{get(8)}'"
    elif event_id == 4672:
        subject_user = get(1)
        description = f"Special privileges assigned to '{subject_user}': {get(4)[:200]}"
    elif event_id == 4688:
        subject_user, process_name, parent_process = get(1), get(5), get(13)
        command_line = get(8) or get(9)
        description = f"Process created by '{subject_user}': {process_name}"
        if parent_process and parent_process != "-":
            description += f" (parent: {parent_process})"
        if command_line and command_line != "-":
            description += f" | CmdLine: {command_line[:200]}"
    elif event_id == 4720:
        subject_user, target_user = get(4), get(0)
        description = f"New user account '{target_user}' created by '{subject_user}'"
    elif event_id == 4740:
        target_user = get(0)
        description = f"Account '{target_user}' locked out"
        if get(1):
            description += f" — triggered by '{get(1)}'"
        if get(2):
            description += f" on '{get(2)}'"
    elif event_id == 4724:
        subject_user, target_user = get(4), get(0)
        description = f"Password reset attempted for '{target_user}' by '{subject_user}'"
    elif event_id in (4728, 4732, 4756):
        target_user, subject_user = get(0), get(6)
        description = f"'{target_user}' added to group '{get(2)}' by '{subject_user}'"
    elif event_id in (4698, 4702):
        subject_user = get(1)
        description = f"Scheduled task '{get(4)}' {'created' if event_id == 4698 else 'updated'} by '{subject_user}'"
    elif event_id == 4719:
        subject_user = get(1)
        description = f"System audit policy changed by '{subject_user}'"
    elif event_id == 1102:
        subject_user = get(1)
        description = f"Security audit log cleared by '{subject_user}'"
    elif event_id == 1104:
        description = "Security event log is full; events may be lost"
    elif event_id in (4768, 4769):
        target_user = get(0)
        source_ip = clean_ip(get(9))
        description = f"{event_type} for '{target_user}'"
        if source_ip:
            description += f" from {source_ip}"
    elif event_id == 4771:
        target_user = get(0)
        source_ip = clean_ip(get(6))
        description = f"Kerberos pre-authentication failed for '{target_user}'"
        if source_ip:
            description += f" from {source_ip}"
        if get(4):
            description += f" — failure code {get(4)}"
    elif event_id == 4776:
        target_user = get(1)
        description = f"NTLM authentication attempt for '{target_user}'"
        if get(2):
            description += f" from workstation '{get(2)}'"
        if get(3) and get(3) != "0x0":
            description += f" — error {get(3)}"
    elif event_id == 4104:
        description = f"PowerShell script block: {get(2)[:500]}"
    elif event_id in (7034, 7035, 7036):
        action = {7034: "crashed", 7035: "received a control", 7036: "changed state"}[event_id]
        description = f"Service '{get(0)}' {action}"
    else:
        description = f"{event_type}; fields: {' | '.join(fields[:8])}"

    attack_type = detect_attack(
        event_id=event_id,
        source_ip=source_ip or "",
        description=description,
        target_user=target_user or subject_user,
        channel=channel,
        raw_line=raw_log,
    )
    if not attack_type:
        return None

    trust_score = score_from_attack(attack_type)
    severity = EventSeverity.HIGH if trust_score >= 90 else EventSeverity.MEDIUM if trust_score >= 70 else EventSeverity.LOW if trust_score >= 40 else EventSeverity.INFORMATIONAL
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source_type=CHANNELS.get(channel, EventSourceType.WINDOWS_SECURITY),
        source_name=channel,
        host=None,
        event_type=event_type,
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        user=target_user or subject_user or None,
        target_user=target_user or None,
        logon_type=logon_type,
        failure_reason=failure_reason,
        process_name=process_name or None,
        process_command_line=command_line or None,
        description=description,
        raw_data={"event_id": event_id, "channel": channel, "inserts": fields, "raw_log": raw_log},
        metadata={"trust_score": trust_score},
    )


class WindowsEventCollector(EventCollector):
    def __init__(self, collector_id: str = "windows-collector"):
        super().__init__(collector_id, EventSourceType.WINDOWS_SECURITY)
        self._win32evtlog = None
        self._cursors = {}
        self._available_channels = []

    async def start(self):
        try:
            import win32evtlog
            self._win32evtlog = win32evtlog
        except ImportError:
            logger.error("pywin32 is unavailable; Windows Event Log collector is disabled.")
            return

        for channel in CHANNELS:
            handle = None
            try:
                handle = self._win32evtlog.OpenEventLog(None, channel)
                flags = self._win32evtlog.EVENTLOG_BACKWARDS_READ | self._win32evtlog.EVENTLOG_SEQUENTIAL_READ
                newest = self._win32evtlog.ReadEventLog(handle, flags, 0) or []
                self._cursors[channel] = max((event.RecordNumber for event in newest), default=0)
                self._available_channels.append(channel)
            except Exception as exc:
                logger.warning("Cannot initialize Windows channel %s: %s", channel, exc)
            finally:
                if handle is not None:
                    try:
                        self._win32evtlog.CloseEventLog(handle)
                    except Exception:
                        pass

        self._running = bool(self._available_channels)
        if not self._running:
            logger.error("No Windows Event Log channels available.")
        else:
            logger.info("Windows Event Log collector initialized for %s channels.", len(self._available_channels))

    async def stop(self):
        self._running = False
        logger.info("Windows Event Log collector stopped.")

    async def collect(self) -> AsyncIterator[EventBatch]:
        if not self._win32evtlog:
            return

        read_flags = self._win32evtlog.EVENTLOG_BACKWARDS_READ | self._win32evtlog.EVENTLOG_SEQUENTIAL_READ
        while self._running:
            for channel in list(self._available_channels):
                handle = None
                try:
                    handle = self._win32evtlog.OpenEventLog(None, channel)
                    observed = []
                    while True:
                        batch = self._win32evtlog.ReadEventLog(handle, read_flags, 0) or []
                        if not batch:
                            break
                        reached_cursor = False
                        for event in batch:
                            record_number = getattr(event, "RecordNumber", 0)
                            if record_number <= self._cursors.get(channel, 0):
                                reached_cursor = True
                                break
                            observed.append(event)
                        if reached_cursor:
                            break

                    for event in sorted(observed, key=lambda item: getattr(item, "RecordNumber", 0)):
                        record_number = getattr(event, "RecordNumber", 0)
                        event_id = event.EventID & 0xFFFF
                        self._cursors[channel] = max(self._cursors.get(channel, 0), record_number)
                        if event_id not in EVENT_IDS:
                            continue

                        try:
                            import win32evtlogutil
                            try:
                                message = win32evtlogutil.SafeFormatMessage(event, channel)
                            except Exception:
                                message = " | ".join(str(value) for value in (event.StringInserts or []))
                            event_time = getattr(event, "TimeGenerated", None)
                            if event_time:
                                try:
                                    event_time = event_time.replace(tzinfo=timezone.utc)
                                except (AttributeError, TypeError):
                                    event_time = None
                            yield EventBatch(
                                events=[RawEvent(
                                    source_type=CHANNELS[channel],
                                    source_name=channel,
                                    host=None,
                                    raw_content=str(message)[:10000],
                                    parsed_data={
                                        "event_id": event_id,
                                        "channel": channel,
                                        "inserts": [str(value) for value in (event.StringInserts or [])],
                                        "record_number": record_number,
                                        "timestamp": event_time.isoformat() if event_time else None,
                                    },
                                    collector_id=self.collector_id,
                                )],
                                source_type=CHANNELS[channel],
                                collector_id=self.collector_id,
                            )
                        except Exception:
                            logger.exception("Failed to package Windows event %s on %s", event_id, channel)
                except Exception as exc:
                    logger.warning("Read failed for Windows channel %s: %s", channel, exc)
                finally:
                    if handle is not None:
                        try:
                            self._win32evtlog.CloseEventLog(handle)
                        except Exception:
                            pass
            await asyncio.sleep(1)


class WindowsEventParser(EventParser):
    def can_parse(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type in {
            EventSourceType.WINDOWS_SECURITY,
            EventSourceType.WINDOWS_SYSTEM,
            EventSourceType.WINDOWS_APPLICATION,
            EventSourceType.WINDOWS_POWERSHELL,
        }

    def parse(self, raw_event: RawEvent) -> Optional[NormalizedEvent]:
        parsed = raw_event.parsed_data or {}
        try:
            event_id = int(parsed.get("event_id") or 0)
        except (TypeError, ValueError):
            return None
        if not event_id:
            return None

        raw_timestamp = parsed.get("timestamp")
        timestamp = None
        if raw_timestamp:
            try:
                timestamp = datetime.fromisoformat(str(raw_timestamp))
            except ValueError:
                pass

        return parse_windows_event(
            event_id,
            parsed.get("inserts") or [],
            parsed.get("channel") or raw_event.source_name or "Security",
            raw_event.raw_content,
            timestamp=timestamp,
        )
