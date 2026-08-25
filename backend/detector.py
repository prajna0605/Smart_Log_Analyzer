from datetime import timedelta

from sqlalchemy.orm import Session

from .models import FlaggedEntry, LogEntry

# Detector Constants
CRITICAL_SEVERITIES = {"CRITICAL", "FATAL", "ERROR"}
BURST_WINDOW_SECONDS = 60
BURST_THRESHOLD_COUNT = 10
OFF_HOURS_START = 22  # 10 PM
OFF_HOURS_END = 5     # 5 AM
SENSITIVE_EVENT_TYPES = {
    "SENSITIVE_DATA_EXPORT",
    "CONFIGURATION_WRITE",
    "SYSTEM_OVERRIDE",
    "ENCRYPTION_KEY_DESTROYED",
    "DELETE",
    "DROP",
}
RARE_THRESHOLD_FREQUENCY = 0.02 # event types representing < 2% of the dataset

def run_anomaly_detector(db: Session):
    """
    Executes rule-based logic to detect anomalies on current log entries.
    Flags entries and saves them to FlaggedEntry.
    Avoids duplicate flagging for same rules.
    """
    # Get only valid log entries
    valid_entries = db.query(LogEntry).filter(LogEntry.is_valid == True).all()
    if not valid_entries:
        return

    # To calculate rare event types, let's build a frequency dictionary
    total_valid = len(valid_entries)
    event_counts = {}
    for entry in valid_entries:
        if entry.event_type:
            event_counts[entry.event_type] = event_counts.get(entry.event_type, 0) + 1

    rare_event_types = {
        etype for etype, count in event_counts.items()
        if (count / total_valid) < RARE_THRESHOLD_FREQUENCY
    }

    # For frequency/burst detection, sort all entries by timestamp and group by source
    # Or query rolling counts. Let's do a sliding window rolling count calculation in python.
    # Group logs by source
    source_logs = {}
    for entry in valid_entries:
        source_logs.setdefault(entry.source, []).append(entry)
    
    # Identify burst entries using two-pointer sliding window O(N log N)
    burst_entry_ids = set()
    for logs in source_logs.values():
        logs.sort(key=lambda x: x.timestamp)
        left = 0
        for right in range(len(logs)):
            while (logs[right].timestamp - logs[left].timestamp).total_seconds() > BURST_WINDOW_SECONDS:
                left += 1
            if (right - left + 1) >= BURST_THRESHOLD_COUNT:
                for k in range(left, right + 1):
                    burst_entry_ids.add(logs[k].id)

    # Batch query existing flags to prevent duplicate flagging
    existing_flags_all = db.query(FlaggedEntry).all()
    existing_rules_map = {}
    for f in existing_flags_all:
        existing_rules_map.setdefault(f.log_entry_id, set()).add(f.detector_rule)

    new_flags = []
    # Apply rules and write FlaggedEntry records
    for entry in valid_entries:
        existing_rules = existing_rules_map.setdefault(entry.id, set())

        # Rule 1: Severity-based (Critical auto-flags)
        if entry.severity in CRITICAL_SEVERITIES:
            rule_name = "SEVERITY_SPIKE"
            if rule_name not in existing_rules:
                existing_rules.add(rule_name)
                new_flags.append(FlaggedEntry(
                    log_entry_id=entry.id,
                    score=1.0,
                    reason=f"Severity of log is {entry.severity}, indicating critical system issue.",
                    detector_rule=rule_name
                ))

        # Rule 2: Request Burst/Frequency
        if entry.id in burst_entry_ids:
            rule_name = "REQUEST_BURST"
            if rule_name not in existing_rules:
                existing_rules.add(rule_name)
                new_flags.append(FlaggedEntry(
                    log_entry_id=entry.id,
                    score=0.9,
                    reason=f"Source {entry.source} generated multiple requests within a 60-second window, exceeding the threshold of {BURST_THRESHOLD_COUNT} requests.",
                    detector_rule=rule_name
                ))

        # Rule 3: Off-pattern Access (Sensitive paths or event types during off-hours 10 PM - 5 AM)
        hour = entry.timestamp.hour
        is_off_hours = hour >= OFF_HOURS_START or hour < OFF_HOURS_END
        if entry.event_type in SENSITIVE_EVENT_TYPES and is_off_hours:
            rule_name = "OFF_HOURS_SENSITIVE_ACCESS"
            if rule_name not in existing_rules:
                existing_rules.add(rule_name)
                new_flags.append(FlaggedEntry(
                    log_entry_id=entry.id,
                    score=0.85,
                    reason=f"Sensitive event '{entry.event_type}' was performed at {entry.timestamp.time()} (off-hours).",
                    detector_rule=rule_name
                ))

        # Rule 4: Rare Event Type
        if entry.event_type in rare_event_types:
            rule_name = "RARE_EVENT_TYPE"
            if rule_name not in existing_rules:
                existing_rules.add(rule_name)
                freq_pct = (event_counts[entry.event_type] / total_valid) * 100
                new_flags.append(FlaggedEntry(
                    log_entry_id=entry.id,
                    score=0.75,
                    reason=f"Event type '{entry.event_type}' occurred rarely in dataset ({freq_pct:.2f}% frequency).",
                    detector_rule=rule_name
                ))

    if new_flags:
        db.add_all(new_flags)
        db.commit()

