"""
SQLite persistence for scan records.

Thread-safe — uses one connection per thread via check_same_thread=False
and explicit locking. The DB file is created automatically.
"""

import sqlite3
import json
import threading
from datetime import datetime, timedelta, timezone
from typing import Optional

import structlog

from .models import ScanRecord, ScanType, GVMScanStatus

log = structlog.get_logger()

DB_PATH = "scans.db"  # overridden by config.scan.db_path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    probe_name TEXT NOT NULL,
    name TEXT,
    target TEXT NOT NULL,
    scan_type TEXT NOT NULL,
    ports TEXT,
    scan_config TEXT,
    external_target_id TEXT,

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

CREATE TABLE IF NOT EXISTS targets (
    external_id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    ports TEXT,
    scan_type TEXT NOT NULL DEFAULT 'full',
    scan_config TEXT,
    criticality TEXT NOT NULL DEFAULT 'medium',
    criticality_weight INTEGER NOT NULL DEFAULT 2,
    scan_frequency_hours INTEGER NOT NULL DEFAULT 168,
    enabled INTEGER NOT NULL DEFAULT 1,
    tags TEXT,

    gvm_target_id TEXT,
    gvm_port_list_id TEXT,

    last_scan_at TEXT,
    next_scan_at TEXT,
    last_scan_id TEXT,

    synced_at TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""

CRITICALITY_WEIGHTS = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


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
                   (scan_id, probe_name, name, target, scan_type, ports,
                    scan_config, external_target_id, gvm_status, gvm_progress, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.scan_id,
                    record.probe_name,
                    record.name,
                    record.target,
                    record.scan_type.value,
                    json.dumps(record.ports) if record.ports else None,
                    record.scan_config,
                    record.external_target_id,
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

    def count_active_per_probe(self) -> dict[str, int]:
        """Count active (not completed) scans per probe via SQL."""
        with self._lock:
            rows = self._conn.execute(
                """SELECT probe_name, COUNT(*) as cnt FROM scans
                   WHERE completed_at IS NULL
                   GROUP BY probe_name"""
            ).fetchall()
        return {row["probe_name"]: row["cnt"] for row in rows}

    def list_all(self) -> list[ScanRecord]:
        """List all scan records, newest first."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM scans ORDER BY created_at DESC"
            ).fetchall()
        return [self._row_to_record(r) for r in rows]

    # =========================================================================
    # Targets
    # =========================================================================

    def upsert_target(self, target: dict):
        """Insert or update a target from the external API."""
        now = datetime.now(timezone.utc).isoformat()
        weight = CRITICALITY_WEIGHTS.get(target.get("criticality", "medium"), 2)
        ports = json.dumps(target["ports"]) if target.get("ports") else None
        tags = json.dumps(target["tags"]) if target.get("tags") else None

        with self._lock:
            existing = self._conn.execute(
                "SELECT external_id FROM targets WHERE external_id = ?",
                (target["id"],)
            ).fetchone()

            if existing:
                self._conn.execute(
                    """UPDATE targets SET
                       host=?, ports=?, scan_type=?, criticality=?,
                       criticality_weight=?, scan_frequency_hours=?,
                       enabled=?, tags=?, synced_at=?
                       WHERE external_id=?""",
                    (
                        target["host"], ports, target.get("scan_type", "full"),
                        target.get("criticality", "medium"), weight,
                        target.get("scan_frequency_hours", 168),
                        1 if target.get("enabled", True) else 0,
                        tags, now, target["id"]
                    )
                )
            else:
                self._conn.execute(
                    """INSERT INTO targets
                       (external_id, host, ports, scan_type, criticality,
                        criticality_weight, scan_frequency_hours, enabled,
                        tags, next_scan_at, synced_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        target["id"], target["host"], ports,
                        target.get("scan_type", "full"),
                        target.get("criticality", "medium"), weight,
                        target.get("scan_frequency_hours", 168),
                        1 if target.get("enabled", True) else 0,
                        tags, now, now, now
                    )
                )
            self._conn.commit()

    def insert_manual_target(self, external_id: str, host: str,
                             scan_type: str = "full",
                             ports: list[int] = None,
                             scan_config: str = None,
                             criticality: str = "medium",
                             scan_frequency_hours: int = 24,
                             tags: dict = None) -> dict:
        """Insert a target manually (without external API sync)."""
        now = datetime.now(timezone.utc).isoformat()
        weight = CRITICALITY_WEIGHTS.get(criticality, 2)
        ports_json = json.dumps(ports) if ports else None
        tags_json = json.dumps(tags) if tags else None

        with self._lock:
            existing = self._conn.execute(
                "SELECT external_id FROM targets WHERE external_id = ?",
                (external_id,)
            ).fetchone()
            if existing:
                raise ValueError(f"Target '{external_id}' already exists")

            self._conn.execute(
                """INSERT INTO targets
                   (external_id, host, ports, scan_type, scan_config,
                    criticality, criticality_weight, scan_frequency_hours,
                    enabled, tags, next_scan_at, synced_at, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (external_id, host, ports_json, scan_type, scan_config,
                 criticality, weight, scan_frequency_hours, 1, tags_json,
                 now, now, now)
            )
            self._conn.commit()

        return self.get_target(external_id)

    def deactivate_missing(self, active_ids: set[str]):
        """Deactivate targets not present in the external API response."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT external_id FROM targets WHERE enabled = 1"
            ).fetchall()
            for row in rows:
                if row["external_id"] not in active_ids:
                    self._conn.execute(
                        "UPDATE targets SET enabled = 0 WHERE external_id = ?",
                        (row["external_id"],)
                    )
            self._conn.commit()

    def get_due_targets(self) -> list[dict]:
        """Get targets that are due for scanning, ordered by criticality (highest first).

        Excludes targets that already have an active (incomplete) scan to prevent duplicates.
        """
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            rows = self._conn.execute(
                """SELECT t.* FROM targets t
                   WHERE t.enabled = 1 AND t.next_scan_at <= ?
                   AND NOT EXISTS (
                       SELECT 1 FROM scans s
                       WHERE s.external_target_id = t.external_id
                       AND s.completed_at IS NULL
                   )
                   ORDER BY t.criticality_weight DESC""",
                (now,)
            ).fetchall()
        return [dict(r) for r in rows]

    def update_target_gvm_ids(self, external_id: str,
                              gvm_target_id: str = None,
                              gvm_port_list_id: str = None):
        """Store GVM resource IDs on a target for reuse across scans."""
        with self._lock:
            if gvm_target_id:
                self._conn.execute(
                    "UPDATE targets SET gvm_target_id = ? WHERE external_id = ?",
                    (gvm_target_id, external_id)
                )
            if gvm_port_list_id:
                self._conn.execute(
                    "UPDATE targets SET gvm_port_list_id = ? WHERE external_id = ?",
                    (gvm_port_list_id, external_id)
                )
            self._conn.commit()

    def update_target_schedule(self, external_id: str, scan_id: str):
        """Update last/next scan times after scheduling a scan."""
        now = datetime.now(timezone.utc)
        with self._lock:
            row = self._conn.execute(
                "SELECT scan_frequency_hours FROM targets WHERE external_id = ?",
                (external_id,)
            ).fetchone()
            if not row:
                return
            freq_hours = row["scan_frequency_hours"]
            next_scan = now + timedelta(hours=freq_hours)
            self._conn.execute(
                """UPDATE targets SET
                   last_scan_at = ?, next_scan_at = ?, last_scan_id = ?
                   WHERE external_id = ?""",
                (now.isoformat(), next_scan.isoformat(), scan_id, external_id)
            )
            self._conn.commit()

    def list_targets(self) -> list[dict]:
        """List all targets."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM targets ORDER BY criticality_weight DESC, host"
            ).fetchall()
        return [dict(r) for r in rows]

    def get_target(self, external_id: str) -> Optional[dict]:
        """Get a single target by external ID."""
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM targets WHERE external_id = ?",
                (external_id,)
            ).fetchone()
        return dict(row) if row else None

    # =========================================================================
    # Scans
    # =========================================================================

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> ScanRecord:
        """Convert a database row to a ScanRecord."""
        return ScanRecord(
            scan_id=row["scan_id"],
            probe_name=row["probe_name"],
            name=row["name"],
            target=row["target"],
            scan_type=ScanType(row["scan_type"]),
            ports=json.loads(row["ports"]) if row["ports"] else None,
            scan_config=row["scan_config"],
            external_target_id=row["external_target_id"],
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
