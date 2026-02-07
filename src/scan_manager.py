"""
Scan Manager — orchestrates the full scan lifecycle.

1. Receives scan request (target + ports)
2. Creates GVM resources (target, port list, task)
3. Starts the scan
4. Polls GVM for real status/progress
5. When done, fetches the full XML report

All status and progress values come directly from GVM — nothing is fabricated.
"""

import asyncio
import time
import threading
from datetime import datetime, timezone
from typing import Optional

import structlog

from .config import AppConfig
from .gvm_client import GVMClient, GVMSession
from .metrics import (
    SCANS_SUBMITTED, SCANS_COMPLETED, SCANS_FAILED,
    SCANS_ACTIVE, SCAN_DURATION, GVM_CONNECTION_ERRORS,
)
from .models import ScanRecord, ScanType, GVMScanStatus

log = structlog.get_logger()

# GVM statuses that mean the scan is finished (no more polling needed)
TERMINAL_STATUSES = {
    GVMScanStatus.DONE.value,
    GVMScanStatus.STOPPED.value,
    GVMScanStatus.INTERRUPTED.value,
}

# GVM statuses that mean the scan failed or was aborted
ERROR_STATUSES = {
    GVMScanStatus.STOPPED.value,
    GVMScanStatus.INTERRUPTED.value,
}


class ScanManager:
    """
    Manages scan lifecycle and in-memory scan tracking.

    Thread-safe access to scan records via a lock.
    """

    def __init__(self, config: AppConfig):
        self.config = config
        self.gvm_client = GVMClient(config.gvm)
        self._scans: dict[str, ScanRecord] = {}
        self._lock = threading.Lock()

    def get_scan(self, scan_id: str) -> Optional[ScanRecord]:
        """Get a scan record by ID."""
        with self._lock:
            record = self._scans.get(scan_id)
            if record:
                return record.model_copy()
            return None

    def list_scans(self) -> list[ScanRecord]:
        """List all scan records."""
        with self._lock:
            return [r.model_copy() for r in self._scans.values()]

    def _update_scan(self, scan_id: str, **kwargs):
        """Update scan record fields."""
        with self._lock:
            record = self._scans.get(scan_id)
            if record:
                for key, value in kwargs.items():
                    setattr(record, key, value)

    def create_scan(self, target: str, scan_type: ScanType,
                    ports: Optional[list[int]] = None) -> ScanRecord:
        """
        Create a new scan record.

        Returns the scan record. Call start_scan() to begin execution.
        """
        record = ScanRecord(
            target=target,
            scan_type=scan_type,
            ports=ports,
        )

        with self._lock:
            self._scans[record.scan_id] = record

        SCANS_SUBMITTED.labels(scan_type=scan_type.value).inc()

        log.info("scan_created",
                 scan_id=record.scan_id,
                 target=target,
                 scan_type=scan_type.value)

        return record.model_copy()

    async def start_scan(self, scan_id: str):
        """Start scan execution in background. Must be called from async context."""
        asyncio.create_task(self._execute_scan(scan_id))

    async def _execute_scan(self, scan_id: str):
        """
        Full scan lifecycle — runs in background.

        1. Connect to GVM
        2. Create resources (port list, target, task)
        3. Start task
        4. Poll status until terminal
        5. Fetch report when done
        """
        record = self.get_scan(scan_id)
        if not record:
            return

        log.info("scan_executing", scan_id=scan_id, target=record.target)
        SCANS_ACTIVE.inc()

        try:
            # Run GVM operations in a thread to avoid blocking the event loop
            # (python-gvm uses synchronous TLS sockets)
            await asyncio.get_running_loop().run_in_executor(
                None, self._run_scan_blocking, scan_id
            )
        except Exception as e:
            log.error("scan_execution_error", scan_id=scan_id, error=str(e))
            SCANS_FAILED.inc()
            self._update_scan(
                scan_id,
                error=str(e),
                completed_at=datetime.now(timezone.utc)
            )
        finally:
            SCANS_ACTIVE.dec()

    def _run_scan_blocking(self, scan_id: str):
        """
        Blocking scan execution — runs in a thread.

        All GVM interactions happen here.
        """
        record = self.get_scan(scan_id)
        if not record:
            return

        try:
            with self.gvm_client.connect() as gvm:
                self._create_gvm_resources(gvm, scan_id, record)
                self._start_and_poll(gvm, scan_id)
                self._collect_report(gvm, scan_id)
                if self.config.scan.cleanup_after_report:
                    self._cleanup_gvm_resources(gvm, scan_id)

        except ConnectionError as e:
            log.error("scan_failed", scan_id=scan_id, error=str(e))
            GVM_CONNECTION_ERRORS.inc()
            SCANS_FAILED.inc()
            self._update_scan(
                scan_id,
                error=str(e),
                completed_at=datetime.now(timezone.utc)
            )
        except Exception as e:
            log.error("scan_failed", scan_id=scan_id, error=str(e))
            SCANS_FAILED.inc()
            self._update_scan(
                scan_id,
                error=str(e),
                completed_at=datetime.now(timezone.utc)
            )

    def _create_gvm_resources(self, gvm: GVMSession, scan_id: str,
                               record: ScanRecord):
        """Create GVM target, port list (if directed), and task."""
        port_list_id = None

        # Create custom port list for directed scans
        if record.scan_type == ScanType.DIRECTED and record.ports:
            port_list_id = gvm.create_port_list(
                name=f"scan-{scan_id}-ports",
                ports=record.ports
            )
            self._update_scan(scan_id, gvm_port_list_id=port_list_id)

        # Create target
        target_id = gvm.create_target(
            name=f"scan-{scan_id}-target",
            hosts=record.target,
            port_list_id=port_list_id,
            default_port_list_name=self.config.scan.default_port_list
        )
        self._update_scan(scan_id, gvm_target_id=target_id)

        # Create task
        task_id = gvm.create_task(
            name=f"scan-{scan_id}",
            target_id=target_id
        )
        self._update_scan(scan_id, gvm_task_id=task_id)

        log.info("gvm_resources_created",
                 scan_id=scan_id,
                 target_id=target_id,
                 task_id=task_id,
                 port_list_id=port_list_id)

    def _start_and_poll(self, gvm: GVMSession, scan_id: str):
        """Start the GVM task and poll until it reaches a terminal status."""
        record = self.get_scan(scan_id)
        if not record or not record.gvm_task_id:
            raise RuntimeError(f"Scan {scan_id} has no GVM task ID")

        # Start task
        report_id = gvm.start_task(record.gvm_task_id)
        self._update_scan(
            scan_id,
            gvm_report_id=report_id,
            started_at=datetime.now(timezone.utc)
        )

        log.info("scan_started",
                 scan_id=scan_id,
                 task_id=record.gvm_task_id,
                 report_id=report_id)

        # Poll for status
        poll_interval = self.config.scan.poll_interval
        max_duration = self.config.scan.max_duration
        start_time = time.monotonic()

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed > max_duration:
                log.warning("scan_timeout",
                            scan_id=scan_id,
                            elapsed_seconds=int(elapsed),
                            max_duration=max_duration)
                gvm.stop_task(record.gvm_task_id)
                self._update_scan(
                    scan_id,
                    error=f"Scan timed out after {int(elapsed)}s (max: {max_duration}s)"
                )
                break

            status_text, progress = gvm.get_task_status(record.gvm_task_id)

            self._update_scan(
                scan_id,
                gvm_status=status_text,
                gvm_progress=progress
            )

            log.info("scan_poll",
                     scan_id=scan_id,
                     gvm_status=status_text,
                     gvm_progress=progress)

            if status_text in TERMINAL_STATUSES:
                break

            time.sleep(poll_interval)

        # Record duration and completion metrics
        duration = time.monotonic() - start_time
        SCAN_DURATION.observe(duration)
        SCANS_COMPLETED.labels(gvm_status=status_text).inc()

        # Set completed timestamp
        self._update_scan(scan_id, completed_at=datetime.now(timezone.utc))

        if status_text in ERROR_STATUSES:
            self._update_scan(
                scan_id,
                error=f"Scan ended with status: {status_text}"
            )

    def _collect_report(self, gvm: GVMSession, scan_id: str):
        """Fetch the XML report and summary after scan completion."""
        record = self.get_scan(scan_id)
        if not record or not record.gvm_report_id:
            return

        # Only collect report if scan completed successfully
        if record.gvm_status != GVMScanStatus.DONE.value:
            log.warning("skipping_report_collection",
                        scan_id=scan_id,
                        status=record.gvm_status)
            return

        log.info("collecting_report", scan_id=scan_id)

        report_xml = gvm.get_report_xml(record.gvm_report_id)
        summary = gvm.parse_report_summary(report_xml)

        self._update_scan(
            scan_id,
            report_xml=report_xml,
            summary={
                "hosts_scanned": summary.hosts_scanned,
                "vulns_high": summary.vulns_high,
                "vulns_medium": summary.vulns_medium,
                "vulns_low": summary.vulns_low,
                "vulns_log": summary.vulns_log,
            }
        )

        log.info("report_collected",
                 scan_id=scan_id,
                 hosts=summary.hosts_scanned,
                 high=summary.vulns_high,
                 medium=summary.vulns_medium,
                 low=summary.vulns_low)

    def _cleanup_gvm_resources(self, gvm: GVMSession, scan_id: str):
        """Delete GVM resources (task, target, port list) created for this scan."""
        record = self.get_scan(scan_id)
        if not record:
            return

        log.info("cleaning_gvm_resources", scan_id=scan_id)

        if record.gvm_task_id:
            try:
                gvm.delete_task(record.gvm_task_id)
            except Exception as e:
                log.warning("cleanup_task_failed", scan_id=scan_id, error=str(e))

        if record.gvm_target_id:
            try:
                gvm.delete_target(record.gvm_target_id)
            except Exception as e:
                log.warning("cleanup_target_failed", scan_id=scan_id, error=str(e))

        if record.gvm_port_list_id:
            try:
                gvm.delete_port_list(record.gvm_port_list_id)
            except Exception as e:
                log.warning("cleanup_port_list_failed", scan_id=scan_id, error=str(e))

        log.info("gvm_resources_cleaned", scan_id=scan_id)
