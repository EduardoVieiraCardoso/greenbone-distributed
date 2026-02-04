"""
Greenbone Central API - Database

Simple in-memory storage with SQLite persistence.
"""

import os
import json
import sqlite3
from datetime import datetime
from typing import Optional
from contextlib import contextmanager

from .models import Job, JobStatus, ProbeInfo, ProbeStatus


# =============================================================================
# Database Setup
# =============================================================================

DB_PATH = os.getenv("DB_PATH", "data/greenbone.db")


def init_db():
    """Initialize database tables"""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    
    with get_connection() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                ports TEXT,
                probe_id TEXT NOT NULL,
                status TEXT NOT NULL,
                progress INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                started_at TEXT,
                completed_at TEXT,
                summary TEXT,
                report_xml TEXT,
                error TEXT
            );
            
            CREATE TABLE IF NOT EXISTS probes (
                probe_id TEXT PRIMARY KEY,
                location TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                status TEXT NOT NULL,
                last_seen TEXT,
                current_job TEXT
            );
            
            CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
            CREATE INDEX IF NOT EXISTS idx_jobs_probe ON jobs(probe_id);
        """)


@contextmanager
def get_connection():
    """Get database connection"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


# =============================================================================
# Job Operations
# =============================================================================

def save_job(job: Job):
    """Save job to database"""
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO jobs 
            (job_id, target, scan_type, ports, probe_id, status, progress,
             created_at, started_at, completed_at, summary, report_xml, error)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            job.job_id,
            job.target,
            job.scan_type.value,
            json.dumps(job.ports) if job.ports else None,
            job.probe_id,
            job.status.value,
            job.progress,
            job.created_at.isoformat(),
            job.started_at.isoformat() if job.started_at else None,
            job.completed_at.isoformat() if job.completed_at else None,
            json.dumps(job.summary) if job.summary else None,
            job.report_xml,
            job.error
        ))


def get_job(job_id: str) -> Optional[Job]:
    """Get job by ID"""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return _row_to_job(row)


def update_job_status(job_id: str, status: JobStatus, **kwargs):
    """Update job status and optional fields"""
    fields = ["status = ?"]
    values = [status.value]
    
    for key, value in kwargs.items():
        if key == "summary" and value:
            fields.append("summary = ?")
            values.append(json.dumps(value))
        elif key == "completed_at" and value:
            fields.append("completed_at = ?")
            values.append(value.isoformat())
        elif key == "started_at" and value:
            fields.append("started_at = ?")
            values.append(value.isoformat())
        elif key == "progress":
            fields.append("progress = ?")
            values.append(value)
        elif key == "error":
            fields.append("error = ?")
            values.append(value)
        elif key == "report_xml":
            fields.append("report_xml = ?")
            values.append(value)
    
    values.append(job_id)
    
    with get_connection() as conn:
        conn.execute(
            f"UPDATE jobs SET {', '.join(fields)} WHERE job_id = ?",
            values
        )


def list_jobs(status: Optional[JobStatus] = None, limit: int = 100) -> list[Job]:
    """List jobs, optionally filtered by status"""
    with get_connection() as conn:
        if status:
            rows = conn.execute(
                "SELECT * FROM jobs WHERE status = ? ORDER BY created_at DESC LIMIT ?",
                (status.value, limit)
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?",
                (limit,)
            ).fetchall()
        
        return [_row_to_job(row) for row in rows]


def _row_to_job(row) -> Job:
    """Convert database row to Job model"""
    from .models import ScanType
    
    return Job(
        job_id=row["job_id"],
        target=row["target"],
        scan_type=ScanType(row["scan_type"]),
        ports=json.loads(row["ports"]) if row["ports"] else None,
        probe_id=row["probe_id"],
        status=JobStatus(row["status"]),
        progress=row["progress"],
        created_at=datetime.fromisoformat(row["created_at"]),
        started_at=datetime.fromisoformat(row["started_at"]) if row["started_at"] else None,
        completed_at=datetime.fromisoformat(row["completed_at"]) if row["completed_at"] else None,
        summary=json.loads(row["summary"]) if row["summary"] else None,
        report_xml=row["report_xml"],
        error=row["error"]
    )


# =============================================================================
# Probe Operations
# =============================================================================

def save_probe(probe: ProbeInfo):
    """Save or update probe"""
    with get_connection() as conn:
        conn.execute("""
            INSERT OR REPLACE INTO probes 
            (probe_id, location, endpoint, status, last_seen, current_job)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            probe.probe_id,
            probe.location,
            probe.endpoint,
            probe.status.value,
            probe.last_seen.isoformat() if probe.last_seen else None,
            probe.current_job
        ))


def get_probe(probe_id: str) -> Optional[ProbeInfo]:
    """Get probe by ID"""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM probes WHERE probe_id = ?", (probe_id,)
        ).fetchone()
        
        if not row:
            return None
        
        return ProbeInfo(
            probe_id=row["probe_id"],
            location=row["location"],
            endpoint=row["endpoint"],
            status=ProbeStatus(row["status"]),
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            current_job=row["current_job"]
        )


def list_probes() -> list[ProbeInfo]:
    """List all probes"""
    with get_connection() as conn:
        rows = conn.execute("SELECT * FROM probes").fetchall()
        
        return [
            ProbeInfo(
                probe_id=row["probe_id"],
                location=row["location"],
                endpoint=row["endpoint"],
                status=ProbeStatus(row["status"]),
                last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
                current_job=row["current_job"]
            )
            for row in rows
        ]


def update_probe_status(probe_id: str, status: ProbeStatus, current_job: Optional[str] = None):
    """Update probe status"""
    with get_connection() as conn:
        conn.execute("""
            UPDATE probes SET status = ?, last_seen = ?, current_job = ?
            WHERE probe_id = ?
        """, (status.value, datetime.utcnow().isoformat(), current_job, probe_id))
