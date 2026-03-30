import os
import httpx
import logging
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from pydantic import BaseModel
from datetime import timedelta, datetime

from backend.database import SessionLocal
from backend.models import Alert
from backend.auth import authenticate_user, create_access_token

logger = logging.getLogger(__name__)
router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login")
def login(data: LoginRequest):
    user = authenticate_user(data.username, data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(data={"sub": user.username}, expires_delta=timedelta(minutes=60))
    return {"access_token": token}


@router.get("/alerts")
def get_alerts(severity: str = Query(None), db: Session = Depends(get_db)):
    q = db.query(Alert).filter(Alert.investigation_status == None).order_by(Alert.timestamp.desc())
    if severity:
        q = q.filter(Alert.severity == severity.upper())
    return [_serialize(a) for a in q.limit(200).all()]


@router.get("/alerts/{alert_id}")
def get_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return _serialize(alert)


@router.get("/stats")
def get_stats(db: Session = Depends(get_db)):
    total = db.query(Alert).count()
    return {
        "total": total,
        "high": db.query(Alert).filter(Alert.severity == "HIGH").count(),
        "medium": db.query(Alert).filter(Alert.severity == "MEDIUM").count(),
        "low": db.query(Alert).filter(Alert.severity == "LOW").count(),
        "priority": db.query(Alert).filter(Alert.priority == True).count(),
        "anomalies": db.query(Alert).filter(Alert.is_anomaly == True).count(),
        "investigated": db.query(Alert).filter(Alert.investigation_status != None).count(),
        "no_data": total == 0,
    }


@router.get("/priority")
def get_priority(db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.priority == True, Alert.investigation_status == None).order_by(Alert.timestamp.desc()).limit(100).all()
    return [_serialize(a) for a in alerts]


@router.get("/investigations")
def get_investigations(db: Session = Depends(get_db)):
    alerts = db.query(Alert).filter(Alert.investigation_status != None).order_by(Alert.investigated_at.desc()).all()
    return [_serialize(a) for a in alerts]


@router.post("/investigate/{alert_id}")
def investigate(alert_id: int, analyst: str = Query(...), status: str = Query(...), reason: str = Query(...), db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.investigation_status = status
    alert.assigned_to = analyst
    alert.investigation_reason = reason
    alert.investigated_at = datetime.utcnow()
    db.commit()
    return {"message": "Alert investigated", "id": alert.id}


@router.post("/analyze/{alert_id}")
async def analyze_alert(alert_id: int, db: Session = Depends(get_db)):
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    related = db.query(Alert).filter(Alert.source_ip == alert.source_ip, Alert.id != alert.id).order_by(Alert.timestamp.desc()).limit(10).all()
    counts = {}
    for r in related:
        counts[r.attack_type] = counts.get(r.attack_type, 0) + 1
    related_summary = "; ".join(f"{v}x {k}" for k, v in counts.items()) if counts else "No prior activity from this IP"

    prompt = f"""You are a senior SOC analyst. Analyze this real security alert.

ALERT DETAILS:
  Alert ID: {alert.id} | Source IP: {alert.source_ip} | Attack Type: {alert.attack_type}
  Severity: {alert.severity} | Trust Score: {alert.trust_score}/100
  Log Source: {alert.log_source or 'N/A'} | Event Type: {alert.event_type or 'N/A'}
  Timestamp: {alert.timestamp} | ML Anomaly: {'Yes' if alert.is_anomaly else 'No'}

EVENT DESCRIPTION (from real log fields):
  {alert.description or 'No description available'}

RELATED ACTIVITY FROM SAME SOURCE IP: {related_summary}

Provide:
1. WHY this is suspicious - reference actual IP, event type, log source
2. MITRE ATT&CK technique if applicable
3. Risk assessment based on trust score and related activity
4. Recommended immediate response actions
Be specific. Reference real field values in every point."""

    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not set. Get a free key at console.groq.com")

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {api_key}",
                    "content-type": "application/json",
                },
                json={
                    "model": "llama-3.3-70b-versatile",
                    "max_tokens": 1024,
                    "messages": [{"role": "user", "content": prompt}],
                },
            )
            resp.raise_for_status()
            data = resp.json()
            report = data["choices"][0]["message"]["content"]
    except Exception as e:
        logger.error(f"Groq API error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

    alert.analysis_report = report
    db.commit()
    return {"alert_id": alert.id, "report": report}


def _serialize(alert: Alert) -> dict:
    return {
        "id": alert.id,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "attack_type": alert.attack_type,
        "severity": alert.severity,
        "trust_score": alert.trust_score,
        "timestamp": alert.timestamp.isoformat() if alert.timestamp else None,
        "log_source": alert.log_source,
        "event_type": alert.event_type,
        "description": alert.description,
        "raw_log": alert.raw_log,
        "priority": alert.priority,
        "assigned_to": alert.assigned_to,
        "analysis_report": alert.analysis_report,
        "investigation_status": alert.investigation_status,
        "investigation_reason": alert.investigation_reason,
        "investigated_at": alert.investigated_at.isoformat() if alert.investigated_at else None,
        "anomaly_score": alert.anomaly_score,
        "is_anomaly": alert.is_anomaly,
    }