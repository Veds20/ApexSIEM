from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text, Float
from datetime import datetime
from .database import Base


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)


class Alert(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True, index=True)

    # ── Core fields ───────────────────────────────────────────────────────
    source_ip = Column(String, index=True)
    destination_ip = Column(String, nullable=True)
    attack_type = Column(String)
    severity = Column(String)
    trust_score = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

    # ── Real log context ─────────────────────────────────────────────────
    log_source = Column(String, nullable=True)      # e.g. "Security", "/var/log/auth.log"
    event_type = Column(String, nullable=True)      # e.g. "Failed logon attempt"
    description = Column(Text, nullable=True)       # human-readable from real fields
    raw_log = Column(Text, nullable=True)           # original raw log line / event text

    # ── Classification ───────────────────────────────────────────────────
    priority = Column(Boolean, default=False)

    # ── Investigation workflow ───────────────────────────────────────────
    assigned_to = Column(String, nullable=True)
    analysis_report = Column(Text, nullable=True)
    investigation_status = Column(String, nullable=True)
    investigation_reason = Column(Text, nullable=True)
    investigated_at = Column(DateTime, nullable=True)

    # ── ML ───────────────────────────────────────────────────────────────
    anomaly_score = Column(Float, nullable=True)
    is_anomaly = Column(Boolean, default=False)