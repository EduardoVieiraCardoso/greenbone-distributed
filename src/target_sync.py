"""
Target Sync & Scheduler.

1. Sync: periodically fetches targets from external REST API, upserts into SQLite
   (only active when source.url is configured)
2. Scheduler: checks which targets are due for scanning, creates scans automatically
   (always active — works with targets inserted manually or via sync)
"""

import asyncio
import json
from datetime import datetime, timezone

import httpx
import structlog

from .config import SourceConfig
from .database import ScanDatabase
from .models import ScanType

log = structlog.get_logger()


class TargetSync:
    """Pulls targets from an external REST API and syncs to SQLite."""

    def __init__(self, config: SourceConfig, db: ScanDatabase):
        self._config = config
        self._db = db

    async def sync(self):
        """Fetch targets from external API and upsert into SQLite."""
        if not self._config.url:
            return

        log.info("target_sync_start", url=self._config.url)

        try:
            headers = {"Content-Type": "application/json"}
            if self._config.auth_token:
                headers["Authorization"] = self._config.auth_token

            async with httpx.AsyncClient(timeout=self._config.timeout) as client:
                resp = await client.get(self._config.url, headers=headers)
                resp.raise_for_status()
                data = resp.json()

            targets = data.get("targets", [])
            active_ids = set()

            for t in targets:
                if not t.get("id") or not t.get("host"):
                    log.warning("target_sync_skip_invalid", target=t)
                    continue
                if not t.get("enabled", True):
                    continue
                self._db.upsert_target(t)
                active_ids.add(t["id"])

            self._db.deactivate_missing(active_ids)

            log.info("target_sync_done",
                     total_received=len(targets),
                     active=len(active_ids))

        except httpx.HTTPStatusError as e:
            log.error("target_sync_http_error",
                      status=e.response.status_code,
                      url=self._config.url)
        except Exception as e:
            log.error("target_sync_error", error=str(e))

    async def run_loop(self):
        """Run sync in a loop at the configured interval."""
        if not self._config.url:
            log.info("target_sync_disabled", reason="source.url not configured")
            return

        while True:
            await self.sync()
            await asyncio.sleep(self._config.sync_interval)


class ScanScheduler:
    """Checks due targets and auto-creates scans.

    Works independently of TargetSync — targets can come from the external
    API sync or be inserted directly into SQLite.
    """

    def __init__(self, db: ScanDatabase, scan_manager,
                 scheduler_interval: int = 60,
                 callback_url: str = "",
                 auth_token: str = "",
                 timeout: int = 30):
        self._db = db
        self._scan_manager = scan_manager
        self._scheduler_interval = scheduler_interval
        self._callback_url = callback_url
        self._auth_token = auth_token
        self._timeout = timeout

    async def check_and_schedule(self):
        """Find targets due for scanning and create scans."""
        due = self._db.get_due_targets()
        if not due:
            return

        log.info("scheduler_due_targets", count=len(due))

        for target in due:
            try:
                scan_type = ScanType(target["scan_type"])
                ports = json.loads(target["ports"]) if target["ports"] else None

                record = self._scan_manager.create_scan(
                    target=target["host"],
                    scan_type=scan_type,
                    ports=ports,
                    name=target["external_id"],
                    scan_config=target.get("scan_config"),
                )

                self._db.update_target_schedule(
                    external_id=target["external_id"],
                    scan_id=record.scan_id
                )

                # Link scan to external target
                self._scan_manager._update_scan(
                    record.scan_id,
                    external_target_id=target["external_id"]
                )

                await self._scan_manager.start_scan(record.scan_id)

                log.info("scheduler_scan_created",
                         external_id=target["external_id"],
                         host=target["host"],
                         scan_id=record.scan_id,
                         criticality=target["criticality"])

            except Exception as e:
                log.error("scheduler_scan_failed",
                          external_id=target["external_id"],
                          error=str(e))

    async def send_callback(self, scan_id: str):
        """Send scan results back to the external API (optional)."""
        if not self._callback_url:
            return

        record = self._scan_manager.get_scan(scan_id)
        if not record or not record.completed_at:
            return

        ext_id = record.external_target_id

        payload = {
            "external_target_id": ext_id,
            "scan_id": record.scan_id,
            "probe_name": record.probe_name,
            "host": record.target,
            "gvm_status": record.gvm_status,
            "completed_at": record.completed_at.isoformat(),
            "summary": record.summary,
        }

        try:
            headers = {"Content-Type": "application/json"}
            if self._auth_token:
                headers["Authorization"] = self._auth_token

            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(
                    self._callback_url,
                    json=payload,
                    headers=headers
                )
                resp.raise_for_status()
                log.info("callback_sent", scan_id=scan_id, status=resp.status_code)
        except Exception as e:
            log.error("callback_failed", scan_id=scan_id, error=str(e))

    async def run_loop(self):
        """Run scheduler in a loop at the configured interval."""
        log.info("scheduler_started", interval=self._scheduler_interval)
        while True:
            await self.check_and_schedule()
            await asyncio.sleep(self._scheduler_interval)
