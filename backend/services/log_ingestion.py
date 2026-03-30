import os, time, logging, threading
from datetime import datetime, timezone
from backend.database import SessionLocal
from backend.models import Alert
from backend.services.ml_engine import detect_anomaly

logger = logging.getLogger(__name__)

WINDOWS_EVENT_IDS = {4624,4625,4648,4656,4663,4672,4688,4698,4702,4719,4720,4722,4724,4725,4726,4728,4732,4738,4740,4756,4768,4769,4771,4776,4798,4799,1100,1102,1104,7034,7035,7036,4104}

def start_log_watcher():
    logger.info("Real log watcher starting...")
    try:
        import win32evtlog
        _watch_windows(win32evtlog)
    except ImportError:
        logger.error("pywin32 not available")

def _watch_windows(win32evtlog):
    channels = ["Security","System","Application","Microsoft-Windows-PowerShell/Operational"]
    handles = {}
    for ch in channels:
        try:
            h = win32evtlog.OpenEventLog(None, ch)
            # seek to end
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            while True:
                evts = win32evtlog.ReadEventLog(h, flags, 0)
                if not evts:
                    break
            handles[ch] = h
            logger.info(f"Watching: {ch}")
        except Exception as e:
            logger.warning(f"Cannot open {ch}: {e}")

    if not handles:
        logger.error("No channels available")
        return

    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    while True:
        for ch, h in handles.items():
            try:
                evts = win32evtlog.ReadEventLog(h, flags, 0)
                for evt in (evts or []):
                    eid = evt.EventID & 0xFFFF
                    if eid not in WINDOWS_EVENT_IDS:
                        continue
                    _process(evt, eid, ch)
            except Exception as e:
                logger.debug(f"Read {ch}: {e}")
        time.sleep(1)

def _process(evt, eid, channel):
    try:
        import win32evtlogutil
        try:
            msg = win32evtlogutil.SafeFormatMessage(evt, channel)
        except:
            msg = " | ".join(str(s) for s in (evt.StringInserts or []))

        inserts = [str(s) for s in (evt.StringInserts or [])]

        from backend.services.log_parser import parse_windows_event
        parsed = parse_windows_event(eid, inserts, channel, msg[:500])
        if parsed:
            _save(parsed)
        else:
            logger.debug(f"EventID {eid} not security-relevant, skipped")
    except Exception as e:
        logger.error(f"Process error EID {eid}: {e}")

def _save(parsed):
    db = SessionLocal()
    try:
        recent = [r.trust_score for r in db.query(Alert).order_by(Alert.timestamp.desc()).limit(50).all()]
        recent.append(parsed["trust_score"])
        anomalies, scores = detect_anomaly(recent)
        is_anomaly = bool(anomalies[-1])
        anomaly_score = float(scores[-1]) if scores else None

        alert = Alert(
            source_ip=parsed.get("source_ip","unknown"),
            destination_ip=parsed.get("destination_ip"),
            attack_type=parsed.get("attack_type","unknown"),
            severity=parsed.get("severity","LOW"),
            trust_score=parsed.get("trust_score",0),
            timestamp=parsed.get("timestamp", datetime.now(timezone.utc)),
            log_source=parsed.get("log_source"),
            event_type=parsed.get("event_type"),
            description=parsed.get("description"),
            priority=parsed.get("severity") == "HIGH" or is_anomaly,
            is_anomaly=is_anomaly,
            anomaly_score=anomaly_score,
        )
        db.add(alert)
        db.commit()
        logger.info(f"[REAL] EID={parsed.get('event_type')} | {alert.attack_type} | {alert.source_ip} | {alert.severity}")
    except Exception as e:
        logger.error(f"DB error: {e}")
        db.rollback()
    finally:
        db.close()
