import asyncio
import json
import logging
import re
from datetime import datetime, timezone
from typing import AsyncIterator, Optional
from ipaddress import ip_address

from ..schemas.normalized import RawEvent, EventBatch, EventSourceType, NormalizedEvent, EventSeverity
from .base import EventCollector, EventParser
from ..services.detection_engine import detect_attack, score_from_attack

logger = logging.getLogger(__name__)

NETWORK_LOG_PATHS = {
    "dns": ["/var/log/named/query.log", "/var/log/dnsmasq.log", "/var/log/unbound.log"],
    "dhcp": ["/var/log/dhcpd.log", "/var/log/dhcp.log"],
    "firewall": ["/var/log/ufw.log", "/var/log/iptables.log", "/var/log/firewall.log"],
    "suricata": ["/var/log/suricata/eve.json", "/var/log/suricata/fast.log"],
    "zeek": ["/usr/local/zeek/logs/conn.log", "/usr/local/zeek/logs/dns.log", "/usr/local/zeek/logs/http.log"],
    "nginx": ["/var/log/nginx/access.log", "/var/log/nginx/error.log"],
    "apache": ["/var/log/apache2/access.log", "/var/log/httpd/access_log"],
}


def source_type_for_path(path: str) -> EventSourceType:
    lower = path.lower()
    if "suricata" in lower or "zeek" in lower:
        return EventSourceType.NETWORK_IDS
    if "dns" in lower:
        return EventSourceType.NETWORK_DNS
    if "dhcp" in lower:
        return EventSourceType.NETWORK_DHCP
    if "nginx" in lower or "apache" in lower or "proxy" in lower:
        return EventSourceType.NETWORK_PROXY
    return EventSourceType.NETWORK_FIREWALL


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


def _timestamp(line: str) -> datetime:
    iso = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)", line)
    if iso:
        try:
            parsed = datetime.fromisoformat(iso.group(1).replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    month_day = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if month_day:
        try:
            current_year = datetime.now(timezone.utc).year
            parsed = datetime.strptime(f"{current_year} {month_day.group(1)}", "%Y %b %d %H:%M:%S")
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


def _to_normalized(source_ip, destination_ip, attack_type, description, timestamp, path, raw_line, event_type=None):
    if not attack_type:
        return None
    score = score_from_attack(attack_type)
    severity = EventSeverity.HIGH if score >= 90 else EventSeverity.MEDIUM if score >= 70 else EventSeverity.LOW if score >= 40 else EventSeverity.INFORMATIONAL
    return NormalizedEvent(
        timestamp=timestamp,
        source_type=source_type_for_path(path),
        source_name=path,
        host=None,
        event_type=event_type or attack_type.replace("_", " ").title(),
        attack_type=attack_type,
        severity=severity,
        source_ip=source_ip,
        destination_ip=destination_ip,
        description=description,
        raw_data={"raw_line": raw_line},
        metadata={"trust_score": score},
    )


def parse_network_log_line(line: str, source_path: str) -> Optional[NormalizedEvent]:
    timestamp = _timestamp(line)
    source_type = source_type_for_path(source_path)
    if source_path.lower().endswith("eve.json"):
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, TypeError):
            return None
        if event.get("event_type") != "alert":
            return None
        alert = event.get("alert") or {}
        source_ip = _clean_ip(event.get("src_ip"))
        destination_ip = _clean_ip(event.get("dest_ip"))
        protocol = event.get("proto") or "unknown protocol"
        signature = alert.get("signature") or "IDS alert"
        category = alert.get("category")
        description = f"Suricata alert: {signature}"
        if category:
            description += f" ({category})"
        description += f"; protocol={protocol}"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line) or "network_intrusion"
        return _to_normalized(source_ip, destination_ip, attack_type, description, timestamp, source_path, line, "Suricata IDS alert")

    suricata = re.search(r"\[Classification:\s*(.*?)\].*?\{(.*?)\}\s*([\d.]+):\d+\s*->\s*([\d.]+)", line)
    if suricata:
        category, protocol, source_raw, dest_raw = suricata.groups()
        source_ip = _clean_ip(source_raw)
        destination_ip = _clean_ip(dest_raw)
        signature = re.search(r"\[\*\*\]\s*\[.*?\]\s*(.*?)\s*\[\*\*\]", line)
        description = f"Suricata alert: {signature.group(1) if signature else category}; protocol={protocol}"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line) or "network_intrusion"
        return _to_normalized(source_ip, destination_ip, attack_type, description, timestamp, source_path, line, "Suricata IDS alert")

    firewall = re.search(r"SRC=([\d.]+).*?DST=([\d.]+).*?DPT=(\d+)", line)
    if firewall:
        source_ip, destination_ip, destination_port = firewall.groups()
        source_ip, destination_ip = _clean_ip(source_ip), _clean_ip(destination_ip)
        description = f"Firewall event to destination port {destination_port}"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line) or "port_scan"
        return _to_normalized(source_ip, destination_ip, attack_type, description, timestamp, source_path, line, "Firewall event")

    if "zeek" in source_path.lower() and not line.startswith("#"):
        parts = line.split("\t")
        if len(parts) >= 8:
            source_ip = _clean_ip(parts[2] if len(parts) > 2 else None)
            destination_ip = _clean_ip(parts[4] if len(parts) > 4 else None)
            protocol = parts[6] if len(parts) > 6 else ""
            service = parts[7] if len(parts) > 7 else ""
            state = parts[11] if len(parts) > 11 else ""
            description = f"Zeek connection record; protocol={protocol}; service={service}; state={state}"
            attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line)
            if attack_type:
                return _to_normalized(source_ip, destination_ip, attack_type, description, timestamp, source_path, line, "Zeek connection")

    dns = re.search(r"queries:.*?([\d.]+)#\d+.*?QUERY:\s*(\S+)", line)
    if dns:
        source_ip, query = _clean_ip(dns.group(1)), dns.group(2)
        description = f"DNS query: {query}"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line)
        if attack_type:
            return _to_normalized(source_ip, None, attack_type, description, timestamp, source_path, line, "DNS query")

    dhcp = re.search(r"DHCPREQUEST.*?from ([\d.]+)", line)
    if dhcp:
        source_ip = _clean_ip(dhcp.group(1))
        description = "DHCP request observed"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line)
        if attack_type:
            return _to_normalized(source_ip, None, attack_type, description, timestamp, source_path, line, "DHCP request")

    web = re.search(r'^([\d.]+) .* "([^"]*)" (\d{3}) \d+', line)
    if web:
        source_ip, request, status_code = _clean_ip(web.group(1)), web.group(2), web.group(3)
        description = f"HTTP response {status_code} for request {request[:180]}"
        attack_type = detect_attack(source_ip=source_ip or "", description=description, raw_line=line)
        if attack_type:
            return _to_normalized(source_ip, None, attack_type, description, timestamp, source_path, line, "HTTP access event")

    return None


class NetworkEventCollector(EventCollector):
    def __init__(self, collector_id: str = "network-collector", log_paths: dict = None):
        super().__init__(collector_id, EventSourceType.NETWORK_FIREWALL)
        self.log_paths = log_paths or NETWORK_LOG_PATHS
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
                    logger.info("Watching network log: %s", path)
                except OSError as exc:
                    logger.debug("Cannot open network log %s: %s", path, exc)
                    if handle:
                        handle.close()
        if not self._file_handles:
            logger.warning("No configured network log files are readable.")

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
                    source_type = source_type_for_path(path)
                    for line in lines:
                        raw_line = line.strip()
                        if raw_line:
                            yield EventBatch(
                                events=[RawEvent(source_type=source_type, source_name=path, host=None, raw_content=raw_line, collector_id=self.collector_id)],
                                source_type=source_type,
                                collector_id=self.collector_id,
                            )
                except (OSError, ValueError) as exc:
                    logger.warning("Read failed for network log %s: %s", path, exc)
            await asyncio.sleep(0.5)


class NetworkEventParser(EventParser):
    def can_parse(self, raw_event: RawEvent) -> bool:
        return raw_event.source_type in {
            EventSourceType.NETWORK_FIREWALL,
            EventSourceType.NETWORK_DNS,
            EventSourceType.NETWORK_DHCP,
            EventSourceType.NETWORK_IDS,
            EventSourceType.NETWORK_PROXY,
        }

    def parse(self, raw_event: RawEvent) -> Optional[NormalizedEvent]:
        return parse_network_log_line(raw_event.raw_content, raw_event.source_name or "unknown")
