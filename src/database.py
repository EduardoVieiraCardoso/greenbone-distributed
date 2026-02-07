"""
SQLite persistence for scan records.

Thread-safe — uses one connection per thread via check_same_thread=False
and explicit locking. The DB file is created automatically.
"""

import sqlite3
import json
import threading
from datetime import datetime, timezone
from typing import Optional

import structlog

from .models import ScanRecord, ScanType, GVMScanStatus

log = structlog.get_logger()

DB_PATH = "scans.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    probe_name TEXT NOT NULL,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    ports TEXT,

    gvm_target_id TEXT,
    gvm_task_id TEXT,
    gvm_report_id TEXT,
    gvm_port_list_id TEXT,

    gvm_status TEXT NOT NULL DEFAULT 'New',
    gvm_progress INTEGER NOT NULL DEFAULT 0,

    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT,

    report_xml TEXT,
    summary TEXT,
    error TEXT
);
"""


class ScanDatabase:
    """Thread-safe SQLite store for scan records."""

    def __init__(self, db_path: str = DB_PATH):
        self._db_path = db_path
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(_SCHEMA)
        log.info("database_initialized", path=db_path)

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def insert(self, record: ScanRecord):
        """Insert a new scan record."""
        with self._lock:
            self._conn.execute(
                """INSERT INTO scans
                   (scan_id, probe_name, target, scan_type, ports,
                    gvm_status, gvm_progress, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.scan_id,
                    record.probe_name,
                    record.target,
                    record.scan_type.value,
                    json.dumps(record.ports) if record.ports else None,
                    record.gvm_status,
                    record.gvm_progress,
                    record.created_at.isoformat(),
                )
            )
            self._conn.commit()

    def update(self, scan_id: str, **kwargs):
        """Update specific fields of a scan record."""
        if not kwargs:
            return

        field_map = {}
        for key, value in kwargs.items():
            if key == "ports":
                field_map["ports"] = json.dumps(value) if value else None
            elif key == "summary":
                field_map["summary"] = json.dumps(value) if value else None
            elif isinstance(value, datetime):
                field_map[key] = value.isoformat()
            elif isinstance(value, ScanType):
                field_map[key] = value.value
            else:
                field_map[key] = value

        set_clause = ", ".join(f"{k} = ?" for k in field_map)
        values = list(field_map.values()) + [scan_id]

        with self._lock:
            self._conn.execute(
                f"UPDATE scans SET {set_clause} WHERE scan_id = ?",
                values
            )
            self._conn.commit()

    def get(self, scan_id: str) -> Optional[ScanRecord]:
        """Get a scan record by ID."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if not row:
            return None
        return self._row_to_record(row)

    def list_all(self) -> list[ScanRecord]:
        """List all scan records, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        """Convert a database row to a ScanRecord."""
        return ScanRecord(
            scan_id=row["scan_id"],
            probe_name=row["probe_name"],
            target=row["target"],
            scan_type=ScanType(row["scan_type"]),
            ports=json.loads(row["ports"]) if row["ports"] else None,
            gvm_target_id=row["gvm_target_id"],
            gvm_task_id=row["gvm_task_id"],
            gvm_report_id=row["gvm_report_id"],
            gvm_port_list_id=row["gvm_port_list_id"],
            gvm_status=row["gvm_status"],
            gvm_progress=row["gvm_progress"],
            created_at=datetime.fromisoformat(row["created_at"]),
            started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
            completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
            report_xml=row["report_xml"],
            summary=json.loads(row["summary"]) if row["summary"] else None,
            error=row["error"],
        )
