# ruff: noqa: DTZ001, DTZ901
import csv
import os
import random
from datetime import datetime, timedelta


def generate_synthetic_dataset(output_path: str):
    """Generates a synthetic log CSV file containing normal log records and specific anomalies."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    start_time = datetime(2026, 8, 24, 0, 0, 0)
    sources = ["192.168.1.50", "192.168.1.51", "10.0.0.12", "172.16.0.4", "api-gateway", "auth-service", "payment-worker"]
    event_types = ["USER_LOGIN", "DATA_FETCH", "PAGE_VIEW", "TRANSACTION", "TOKEN_REFRESH", "LOGOUT", "CONFIG_LOAD"]
    severities = ["INFO", "INFO", "INFO", "INFO", "WARNING", "DEBUG"] # Weighted towards INFO

    rows = []

    # 1. Generate mostly normal data (200 records)
    for i in range(200):
        offset_seconds = random.randint(0, 86400) # randomly distributed across 24h
        log_time = start_time + timedelta(seconds=offset_seconds)
        source = random.choice(sources)
        event_type = random.choice(event_types)
        severity = random.choice(severities)
        raw_message = f"Process successfully completed for action {event_type.lower()}."
        rows.append([log_time.isoformat(), source, event_type, severity, raw_message])

    # 2. Add Deliberate Anomalies:
    
    # Anomaly A: Severity Spikes (FATAL / CRITICAL logs) -> 4 rows
    rows.append([
        (start_time + timedelta(hours=3, minutes=15)).isoformat(),
        "database-master",
        "DB_CONNECTION_LOST",
        "FATAL",
        "Could not connect to database on host 10.0.0.5: Connection pool exhausted."
    ])
    rows.append([
        (start_time + timedelta(hours=10, minutes=45)).isoformat(),
        "payment-gateway",
        "TRANSACTION_FAILED",
        "CRITICAL",
        "Transaction TXN_99812 failed: Gateway timeout."
    ])
    rows.append([
        (start_time + timedelta(hours=16, minutes=5)).isoformat(),
        "auth-service",
        "KEY_ROTATION_FAIL",
        "CRITICAL",
        "Failed to rotate security certificates: write permission denied."
    ])
    rows.append([
        (start_time + timedelta(hours=22, minutes=30)).isoformat(),
        "kernel",
        "DISK_FULL",
        "FATAL",
        "FileSystem /dev/sda1 is 100% full. System halting."
    ])

    # Anomaly B: Frequency/burst detection (IP source sending > 10 requests within a single minute) -> 12 rows
    burst_source = "198.51.100.42"
    burst_time = start_time + timedelta(hours=14, minutes=30)
    for i in range(12):
        # All within 14:30:00 to 14:30:50
        sec_offset = i * 4
        rows.append([
            (burst_time + timedelta(seconds=sec_offset)).isoformat(),
            burst_source,
            "API_REQUEST",
            "INFO",
            f"Rapid request burst from external host. Request ID: {1000 + i}"
        ])

    # Anomaly C: Off-pattern access to sensitive paths (sensitive event type/path accessed during odd hours: 10 PM - 5 AM) -> 2 rows
    rows.append([
        (start_time + timedelta(hours=2, minutes=15)).isoformat(),
        "192.168.1.189",
        "SENSITIVE_DATA_EXPORT",
        "WARNING",
        "Exported user credential hashes list via admin console."
    ])
    rows.append([
        (start_time + timedelta(hours=23, minutes=55)).isoformat(),
        "192.168.1.201",
        "CONFIGURATION_WRITE",
        "WARNING",
        "Directly updated config key global_routing_table."
    ])

    # Anomaly D: Rare event type (e.g. SYSTEM_OVERRIDE / ENCRYPTION_KEY_DESTROYED) -> 2 rows
    rows.append([
        (start_time + timedelta(hours=9, minutes=12)).isoformat(),
        "admin-console",
        "SYSTEM_OVERRIDE",
        "WARNING",
        "Manual system override triggered by user operator_01."
    ])
    rows.append([
        (start_time + timedelta(hours=15, minutes=40)).isoformat(),
        "kms-service",
        "ENCRYPTION_KEY_DESTROYED",
        "WARNING",
        "Encryption key vault_prod_master_key has been permanently deleted."
    ])

    # 3. Add Malformed/Invalid Logs to test ingestion engine validations -> 3 rows
    # Row with missing timestamp
    rows.append([
        "",
        "192.168.1.55",
        "USER_LOGIN",
        "INFO",
        "Missing timestamp log entry."
    ])
    # Row with missing source
    rows.append([
        (start_time + timedelta(hours=8)).isoformat(),
        "",
        "DATA_FETCH",
        "INFO",
        "Missing source field."
    ])
    # Malformed timestamp structure
    rows.append([
        "2026-08-24T99:99:99",
        "192.168.1.56",
        "LOGOUT",
        "INFO",
        "Malformed timestamp log entry."
    ])

    # Sort rows by timestamp (placing malformed/empty timestamp entries at the end or handling gracefully)
    def parse_time(row):
        try:
            return datetime.fromisoformat(row[0])
        except ValueError:
            return datetime.max  # Put malformed ones at the bottom

    rows.sort(key=parse_time)

    # Write CSV
    with open(output_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["timestamp", "source", "event_type", "severity", "raw_message"])
        writer.writerows(rows)

    print(f"Synthesized log dataset generated successfully at: {output_path} ({len(rows)} total lines).")

if __name__ == "__main__":
    generate_synthetic_dataset("data/logs.csv")
