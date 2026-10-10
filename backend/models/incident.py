from sqlalchemy import Column, Integer, String, DateTime, Float, Text, ForeignKey, Table, Enum as SQLEnum
from sqlalchemy.orm import relationship
from datetime import datetime
from enum import Enum as PyEnum
from uuid import uuid4

from ..database import Base


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
