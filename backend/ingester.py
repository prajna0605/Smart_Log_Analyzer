import csv
import json
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .models import IngestionSummary, LogEntry

TIMESTAMP_ALIASES = {"timestamp", "datetime", "time", "date", "created_at", "log_time", "ts"}
SOURCE_ALIASES = {"source", "ip_address", "ip", "host", "client_ip", "source_ip", "src", "hostname", "user_ip", "origin"}
EVENT_TYPE_ALIASES = {"event_type", "request_type", "action", "event", "method", "path", "uri", "command", "operation", "type"}
SEVERITY_ALIASES = {"severity", "status_code", "status", "level", "log_level", "error_level", "priority"}
RAW_MESSAGE_ALIASES = {"raw_message", "message", "user_agent", "details", "description", "log", "msg"}


def normalize_key(k: str) -> str:
    return (k or "").strip().lower().replace(" ", "_")


def map_severity_value(val: str) -> str:
    val_upper = (val or "").strip().upper()
    if val_upper in {"500", "502", "503", "504", "FATAL", "CRITICAL"}:
        return "CRITICAL"
    if val_upper in {"400", "401", "403", "404", "ERROR", "WARN", "WARNING"}:
        return "WARNING" if val_upper in {"403", "404", "WARN", "WARNING"} else "ERROR"
    if val_upper in {"200", "201", "204", "301", "302", "INFO", "DEBUG"}:
        return "INFO"
    return val_upper or "INFO"


def extract_row_fields(row: dict):
    norm_row = {normalize_key(k): (v or "").strip() for k, v in row.items() if k}

    raw_timestamp = ""
    raw_source = ""
    event_type = ""
    severity = ""
    raw_message = ""

    # Search by alias dictionaries with independent checks
    for k, v in norm_row.items():
        if not raw_timestamp and k in TIMESTAMP_ALIASES:
            raw_timestamp = v
        if not raw_source and k in SOURCE_ALIASES:
            raw_source = v
        if not event_type and k in EVENT_TYPE_ALIASES:
            event_type = v
        if not severity and k in SEVERITY_ALIASES:
            severity = map_severity_value(v)
        if not raw_message and k in RAW_MESSAGE_ALIASES:
            raw_message = v

    # Build a combined raw message containing all key-values for full traceability
    kv_parts = [f"{k}: {v}" for k, v in row.items() if v]
    combined_message = raw_message or " | ".join(kv_parts)

    return raw_timestamp, raw_source, event_type or None, severity or None, combined_message or None


def ingest_csv_logs(file_path: str, filename: str, db: Session) -> IngestionSummary:
    """
    Parses logs from the CSV file adaptively.
    Validates that:
    - timestamp is present and is in valid ISO or standard datetime format.
    - source is present.
    If valid, inserts into log_entries (is_valid=True).
    If invalid, inserts into log_entries (is_valid=False, validation_error=reason)
    Tracks loaded/rejected rows and logs detail in IngestionSummary.
    """
    total_rows = 0
    loaded_rows = 0
    rejected_rows = 0
    rejected_details = []
    log_entries = []

    with open(file_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            total_rows += 1

            raw_timestamp, raw_source, event_type, severity, raw_message = extract_row_fields(row)

            # Validation
            validation_errors = []
            parsed_timestamp = None

            if not raw_timestamp:
                validation_errors.append("Missing timestamp")
            else:
                try:
                    # Try reading standard ISO format
                    parsed_timestamp = datetime.fromisoformat(raw_timestamp)
                except ValueError:
                    try:
                        parsed_timestamp = datetime.strptime(raw_timestamp, "%Y-%m-%d %H:%M:%S")  # noqa: DTZ007
                    except ValueError:
                        validation_errors.append(f"Malformed timestamp: '{raw_timestamp}'")

            if not raw_source:
                validation_errors.append("Missing source")

            is_valid = len(validation_errors) == 0
            err_msg = "; ".join(validation_errors) if not is_valid else None

            # If not parseable timestamp, assign current timestamp so we can save it in DB
            db_timestamp = parsed_timestamp if parsed_timestamp else datetime.now(timezone.utc).replace(tzinfo=None)

            log_entry = LogEntry(
                timestamp=db_timestamp,
                source=raw_source or "UNKNOWN",
                event_type=event_type,
                severity=severity,
                raw_message=raw_message,
                is_valid=is_valid,
                validation_error=err_msg
            )
            log_entries.append(log_entry)

            if is_valid:
                loaded_rows += 1
            else:
                rejected_rows += 1
                rejected_details.append({
                    "row_index": idx,
                    "raw_row": row,
                    "error": err_msg
                })

        db.add_all(log_entries)
        db.commit()

        # Save IngestionSummary
        summary = IngestionSummary(
            filename=filename,
            total_rows=total_rows,
            loaded_rows=loaded_rows,
            rejected_rows=rejected_rows,
            rejected_details=json.dumps(rejected_details)
        )
        db.add(summary)
        db.commit()
        db.refresh(summary)

        return summary

