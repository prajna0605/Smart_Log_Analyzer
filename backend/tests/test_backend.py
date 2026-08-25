import os
import tempfile
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.database import Base
from backend.detector import run_anomaly_detector
from backend.ingester import extract_row_fields, ingest_csv_logs, map_severity_value
from backend.models import FlaggedEntry, LogEntry


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


def test_map_severity_value():
    assert map_severity_value("500") == "CRITICAL"
    assert map_severity_value("fatal") == "CRITICAL"
    assert map_severity_value("404") == "WARNING"
    assert map_severity_value("400") == "ERROR"
    assert map_severity_value("200") == "INFO"
    assert map_severity_value("UNKNOWN_VAL") == "UNKNOWN_VAL"


def test_extract_row_fields():
    row = {
        "timestamp": "2026-08-24T12:00:00",
        "ip_address": "192.168.1.1",
        "action": "USER_LOGIN",
        "level": "INFO",
        "message": "User logged in successfully"
    }
    ts, src, event, sev, msg = extract_row_fields(row)
    assert ts == "2026-08-24T12:00:00"
    assert src == "192.168.1.1"
    assert event == "USER_LOGIN"
    assert sev == "INFO"
    assert msg == "User logged in successfully"


def test_ingest_csv_logs_valid_and_invalid(db_session):
    csv_content = """timestamp,source,event_type,severity,raw_message
2026-08-24T10:00:00,10.0.0.1,DATA_FETCH,INFO,Success
,10.0.0.2,DATA_FETCH,INFO,Missing timestamp
2026-08-24T10:05:00,,DATA_FETCH,INFO,Missing source
2026-08-24T99:99:99,10.0.0.4,DATA_FETCH,INFO,Malformed timestamp
"""
    with tempfile.NamedTemporaryFile("w+", delete=False, suffix=".csv") as tmp:
        tmp.write(csv_content)
        tmp_path = tmp.name

    try:
        summary = ingest_csv_logs(tmp_path, "test.csv", db_session)
        assert summary.total_rows == 4
        assert summary.loaded_rows == 1
        assert summary.rejected_rows == 3

        logs = db_session.query(LogEntry).all()
        assert len(logs) == 4
        valid_logs = [l for l in logs if l.is_valid]
        assert len(valid_logs) == 1
        assert valid_logs[0].source == "10.0.0.1"
    finally:
        os.remove(tmp_path)


def test_detector_rules(db_session):
    now = datetime(2026, 8, 24, 23, 30, 0)  # 11:30 PM (off-hours)

    # 1. Severity Spike
    log_critical = LogEntry(
        timestamp=now,
        source="server-1",
        event_type="DB_ERROR",
        severity="FATAL",
        raw_message="Database failure",
        is_valid=True
    )
    db_session.add(log_critical)

    # 2. Off-hours sensitive access
    log_off_hours = LogEntry(
        timestamp=now,
        source="admin-pc",
        event_type="SENSITIVE_DATA_EXPORT",
        severity="WARNING",
        raw_message="Data export",
        is_valid=True
    )
    db_session.add(log_off_hours)

    # 3. Burst anomaly (11 requests from same source within 60s)
    burst_time = datetime(2026, 8, 24, 12, 0, 0)
    for i in range(11):
        db_session.add(LogEntry(
            timestamp=burst_time + timedelta(seconds=i * 3),
            source="burst-ip",
            event_type="API_CALL",
            severity="INFO",
            raw_message=f"Request {i}",
            is_valid=True
        ))

    db_session.commit()

    # Run detector
    run_anomaly_detector(db_session)

    flags = db_session.query(FlaggedEntry).all()
    rules = {f.detector_rule for f in flags}

    assert "SEVERITY_SPIKE" in rules
    assert "OFF_HOURS_SENSITIVE_ACCESS" in rules
    assert "REQUEST_BURST" in rules
