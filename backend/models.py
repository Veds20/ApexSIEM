from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float, ForeignKey, Table, UniqueConstraint, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum as PyEnum
from uuid import uuid4

from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


class IncidentStatus(str, PyEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class IncidentSeverity(str, PyEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


incident_alerts = Table(
    "incident_alerts",
    Base.metadata,
    Column("incident_id", Integer, ForeignKey("incidents.id"), primary_key=True),
    Column("alert_id", Integer, ForeignKey("alerts.id"), primary_key=True),
)


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(String(36), unique=True, index=True, default=lambda: str(uuid4()))
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(SQLEnum(IncidentSeverity), default=IncidentSeverity.MEDIUM, index=True)
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True)
    confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)
    assigned_to = Column(String(100), nullable=True)
    assigned_at = Column(DateTime, nullable=True)
    created_by = Column(String(100), nullable=True)
    mitre_techniques = Column(Text, nullable=True)
    threat_intelligence = Column(Text, nullable=True)
    timeline = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    resolution = Column(Text, nullable=True)
    false_positive_reason = Column(Text, nullable=True)
    alerts = relationship("Alert", secondary=incident_alerts, back_populates="incidents")

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if self.severity else None,
            "status": self.status.value if self.status else None,
            "confidence": self.confidence,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "closed_at": self.closed_at.isoformat() if self.closed_at else None,
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "created_by": self.created_by,
            "mitre_techniques": self.mitre_techniques,
            "threat_intelligence": self.threat_intelligence,
            "timeline": self.timeline,
            "evidence": self.evidence,
            "resolution": self.resolution,
            "false_positive_reason": self.false_positive_reason,
            "alert_count": len(self.alerts) if self.alerts else 0,
            "alert_ids": [alert.id for alert in self.alerts] if self.alerts else [],
        }


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)

    source_ip = Column(String, index=True)
    destination_ip = Column(String, nullable=True)
    attack_type = Column(String)
    severity = Column(String)
    trust_score = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

    source_type = Column(String, nullable=True, index=True)
    source_name = Column(String, nullable=True)
    collector = Column(String, nullable=True)
    source_event_id = Column(String, nullable=True)
    event_timestamp = Column(DateTime, nullable=True, index=True)
    ingestion_timestamp = Column(DateTime, nullable=True, index=True)
    event_key = Column(String, nullable=True, unique=True, index=True)
    normalized_event_id = Column(Integer, ForeignKey("normalized_events.id"), nullable=True, index=True)

    log_source = Column(String, nullable=True)
    event_type = Column(String, nullable=True)
    description = Column(Text, nullable=True)
    raw_log = Column(Text, nullable=True)
    priority = Column(Boolean, default=False)

    assigned_to = Column(String, nullable=True)
    analysis_report = Column(Text, nullable=True)
    investigation_status = Column(String, nullable=True)
    investigation_reason = Column(Text, nullable=True)
    investigated_at = Column(DateTime, nullable=True)

    anomaly_score = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, default=False)

    incidents = relationship("Incident", secondary=incident_alerts, back_populates="alerts")
    normalized_event = relationship("NormalizedEventRecord", back_populates="alerts")


class NormalizedEventRecord(Base):
    __tablename__ = "normalized_events"

    id = Column(Integer, primary_key=True, index=True)
    event_key = Column(String, nullable=False, unique=True, index=True)
    source_type = Column(String, nullable=False, index=True)
    source_name = Column(String, nullable=False)
    collector = Column(String, nullable=False)
    source_event_id = Column(String, nullable=False)
    event_timestamp = Column(DateTime, nullable=False, index=True)
    ingestion_timestamp = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    raw_evidence = Column(Text, nullable=False)
    normalized_data = Column(Text, nullable=False)

    alerts = relationship("Alert", back_populates="normalized_event")


class CollectorHealth(Base):
    __tablename__ = "collector_health"

    id = Column(Integer, primary_key=True, index=True)
    collector_name = Column(String, nullable=False, unique=True, index=True)
    source_type = Column(String, nullable=False)
    status = Column(String, nullable=False, default="DISCONNECTED")
    last_event_received = Column(DateTime, nullable=True)
    events_per_second = Column(Float, nullable=False, default=0.0)
    last_error = Column(Text, nullable=True)
    started_at = Column(DateTime, nullable=True)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)


class CollectorCursor(Base):
    __tablename__ = "collector_cursors"

    id = Column(Integer, primary_key=True, index=True)
    collector_name = Column(String, nullable=False, index=True)
    source_name = Column(String, nullable=False)
    cursor_value = Column(String, nullable=False)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)

    __table_args__ = (UniqueConstraint("collector_name", "source_name", name="uq_collector_cursor"),)
