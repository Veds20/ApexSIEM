import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any
from enum import Enum

from ..models import Alert

logger = logging.getLogger(__name__)


class CorrelationType(str, Enum):
    SAME_USER = "same_user"
    SAME_HOST = "same_host"
    SAME_SOURCE_IP = "same_source_ip"
    SAME_DESTINATION_IP = "same_destination_ip"
    SAME_PROCESS = "same_process"
    TIME_WINDOW = "time_window"
    EVENT_SEQUENCE = "event_sequence"
    AUTH_CHAIN = "auth_chain"
    NETWORK_RELATIONSHIP = "network_relationship"
    ATTACK_TECHNIQUE = "attack_technique"
    CLOUD_IDENTITY = "cloud_identity"


class CorrelationRule:
    def __init__(self, name: str, correlation_type: CorrelationType, time_window_seconds: int = 300,
                 min_events: int = 2, conditions: Dict[str, Any] = None):
        self.name = name
        self.correlation_type = correlation_type
        self.time_window_seconds = time_window_seconds
        self.min_events = min_events
        self.conditions = conditions or {}

    def matches(self, events: List[Alert]) -> bool:
        return len(events) >= self.min_events


DEFAULT_CORRELATION_RULES = [
    CorrelationRule("brute_force_to_success", CorrelationType.AUTH_CHAIN, 600, 2,
        {"sequence": [{"attack_type": "brute_force", "min_count": 5}, {"attack_type": "successful_logon", "within_seconds": 600}]}),
    CorrelationRule("privilege_escalation_chain", CorrelationType.EVENT_SEQUENCE, 900, 2,
        {"sequence": [{"attack_type": "privilege_escalation"}, {"attack_type": "suspicious_process", "within_seconds": 900}]}),
    CorrelationRule("lateral_movement_chain", CorrelationType.EVENT_SEQUENCE, 1800, 3,
        {"sequence": [{"attack_type": "lateral_movement"}, {"attack_type": "privilege_escalation", "within_seconds": 1800}, {"attack_type": "suspicious_process", "within_seconds": 1800}]}),
    CorrelationRule("credential_access_to_impact", CorrelationType.EVENT_SEQUENCE, 3600, 2,
        {"sequence": [{"attack_type": "credential_access"}, {"attack_type": "data_exfiltration", "within_seconds": 3600}]}),
    CorrelationRule("multi_host_brute_force", CorrelationType.SAME_SOURCE_IP, 1800, 3, {"unique_hosts": 3}),
    CorrelationRule("account_compromise", CorrelationType.SAME_USER, 3600, 3,
        {"sequence": [{"attack_type": "brute_force"}, {"attack_type": "successful_logon"}, {"attack_type": "privilege_escalation", "within_seconds": 3600}]}),
    CorrelationRule("persistence_mechanism", CorrelationType.EVENT_SEQUENCE, 7200, 2,
        {"sequence": [{"attack_type": "scheduled_task_created"}, {"attack_type": "service_installed", "within_seconds": 7200}]}),
]


class CorrelationEngine:
    def __init__(self, rules: List[CorrelationRule] = None):
        self.rules = rules or DEFAULT_CORRELATION_RULES
        self.event_buffer: List[Alert] = []
        self.max_buffer_size = 10000
        self.max_buffer_age = timedelta(hours=24)

    def add_event(self, event: Alert):
        self.event_buffer.append(event)
        self._prune_buffer()

    def _prune_buffer(self):
        cutoff = datetime.utcnow() - self.max_buffer_age
        self.event_buffer = [e for e in self.event_buffer if e.timestamp and e.timestamp > cutoff]
        if len(self.event_buffer) > self.max_buffer_size:
            self.event_buffer = self.event_buffer[-self.max_buffer_size:]

    def find_correlations(self, new_event: Alert) -> List[Dict[str, Any]]:
        correlations = []
        for rule in self.rules:
            matches = self._evaluate_rule(rule, new_event)
            if matches:
                correlations.append({
                    "rule_name": rule.name,
                    "correlation_type": rule.correlation_type.value,
                    "matched_events": [self._serialize_event(e) for e in matches],
                    "time_window_seconds": rule.time_window_seconds,
                })
        return correlations

    def _evaluate_rule(self, rule: CorrelationRule, new_event: Alert) -> List[Alert]:
        cutoff = datetime.utcnow() - timedelta(seconds=rule.time_window_seconds)
        relevant = [e for e in self.event_buffer if e.timestamp and e.timestamp >= cutoff and e.id != new_event.id]

        if rule.correlation_type == CorrelationType.SAME_USER:
            relevant = [e for e in relevant if getattr(e, "user", None) and getattr(new_event, "user", None) and e.user == new_event.user]
        elif rule.correlation_type == CorrelationType.SAME_HOST:
            relevant = [e for e in relevant if getattr(e, "host", None) and getattr(new_event, "host", None) and e.host == new_event.host]
        elif rule.correlation_type == CorrelationType.SAME_SOURCE_IP:
            relevant = [e for e in relevant if e.source_ip and new_event.source_ip and e.source_ip == new_event.source_ip]
        elif rule.correlation_type == CorrelationType.SAME_DESTINATION_IP:
            relevant = [e for e in relevant if e.destination_ip and new_event.destination_ip and e.destination_ip == new_event.destination_ip]
        elif rule.correlation_type == CorrelationType.SAME_PROCESS:
            relevant = [e for e in relevant if getattr(e, "process_name", None) and getattr(new_event, "process_name", None) and e.process_name == new_event.process_name]

        if "unique_hosts" in rule.conditions:
            unique_hosts = {getattr(e, "host", None) for e in relevant if getattr(e, "host", None)}
            if len(unique_hosts) < rule.conditions["unique_hosts"]:
                return []

        if "sequence" in rule.conditions:
            matched = self._match_sequence(rule.conditions["sequence"], relevant, new_event)
            if matched:
                return matched

        return relevant + [new_event] if len(relevant) >= rule.min_events - 1 else []

    def _match_sequence(self, sequence: List[Dict], events: List[Alert], new_event: Alert) -> List[Alert]:
        matched = []
        index = 0
        all_events = sorted(events + [new_event], key=lambda event: event.timestamp or datetime.min)
        for step in sequence:
            found = False
            for i in range(index, len(all_events)):
                event = all_events[i]
                if self._event_matches_step(event, step):
                    matched.append(event)
                    index = i + 1
                    found = True
                    break
            if not found:
                return []
        return matched if len(matched) >= len(sequence) else []

    def _event_matches_step(self, event: Alert, step: Dict) -> bool:
        attack_type = step.get("attack_type")
        return event.attack_type == attack_type if attack_type else True

    def _serialize_event(self, event: Alert) -> Dict[str, Any]:
        return {
            "id": event.id,
            "timestamp": event.timestamp.isoformat() if event.timestamp else None,
            "source_ip": event.source_ip,
            "attack_type": event.attack_type,
            "severity": event.severity,
            "user": getattr(event, "user", None),
            "host": getattr(event, "host", None),
            "process_name": getattr(event, "process_name", None),
        }


correlation_engine = CorrelationEngine()
