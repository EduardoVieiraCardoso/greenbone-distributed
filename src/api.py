"""
Greenbone Adapter API — HTTP endpoints for scan management.

Endpoints:
  POST /scans          — Submit a new scan (auto-selects least-busy probe)
  GET  /scans          — List all scans
  GET  /scans/{id}     — Get scan status (real GVM status + progress)
  GET  /scans/{id}/report — Get full XML report (only when Done)
  GET  /probes         — List all probes and their status
  GET  /health         — Health check (tests all probes)
  GET  /metrics        — Prometheus metrics
"""

from fastapi import FastAPI, HTTPException, Request
from contextlib import asynccontextmanager

import structlog
from prometheus_client import make_asgi_app

from .config import AppConfig
from .scan_manager import ScanManager
from .models import (
    ScanRequest, ScanCreatedResponse, ScanStatusResponse,
    ScanResultResponse, ScanType,
)

log = structlog.get_logger()


def create_app(config: AppConfig) -> FastAPI:
    """Create and configure the FastAPI application."""

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        app.state.scan_manager = ScanManager(config)
        log.info("adapter_starting")
        yield
        log.info("adapter_shutdown")

    app = FastAPI(
        title="Greenbone Adapter",
        description="Bridge service for Greenbone/OpenVAS via GMP protocol",
        version="1.0.0",
        lifespan=lifespan,
    )

    app.add_api_route("/health", health, methods=["GET"])
    app.add_api_route("/probes", list_probes, methods=["GET"])
    app.add_api_route("/scans", create_scan, methods=["POST"],
                      response_model=ScanCreatedResponse)
    app.add_api_route("/scans", list_scans, methods=["GET"])
    app.add_api_route("/scans/{scan_id}", get_scan_status, methods=["GET"],
                      response_model=ScanStatusResponse)
    app.add_api_route("/scans/{scan_id}/report", get_scan_report, methods=["GET"],
                      response_model=ScanResultResponse)

    app.mount("/metrics", make_asgi_app())

    return app


# =============================================================================
# Endpoints
# =============================================================================

async def health(request: Request):
    """Health check — tests connectivity to all GVM probes."""
    manager: ScanManager = request.app.state.scan_manager
    probes_status = {}
    all_healthy = True

    for name in manager.probe_names:
        try:
            client = manager.get_probe_client(name)
            with client.connect() as gvm:
                gvm.get_scanners()
            probes_status[name] = "connected"
        except Exception as e:
            probes_status[name] = str(e)
            all_healthy = False

    result = {"status": "healthy" if all_healthy else "degraded", "probes": probes_status}

    if not all_healthy:
        raise HTTPException(status_code=503, detail=result)
    return result


async def list_probes(request: Request):
    """List all configured probes and their active scan counts."""
    manager: ScanManager = request.app.state.scan_manager
    return {"probes": manager.get_probes_status()}


async def create_scan(request: Request, body: ScanRequest):
    """
    Submit a new scan.

    The scan starts immediately in the background. Use GET /scans/{id}
    to poll for real GVM status and progress.
    """
    if body.scan_type == ScanType.DIRECTED and not body.ports:
        raise HTTPException(
            status_code=422,
            detail="Directed scan requires 'ports' field"
        )

    manager: ScanManager = request.app.state.scan_manager

    try:
        record = manager.create_scan(
            target=body.target,
            scan_type=body.scan_type,
            ports=body.ports,
            probe_name=body.probe_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=422, detail=str(e))

    await manager.start_scan(record.scan_id)

    return ScanCreatedResponse(
        scan_id=record.scan_id,
        probe_name=record.probe_name,
        message="Scan submitted"
    )


async def list_scans(request: Request):
    """List all scans with their current GVM status."""
    manager: ScanManager = request.app.state.scan_manager
    scans = manager.list_scans()
    return {
        "total": len(scans),
        "scans": [
            {
                "scan_id": s.scan_id,
                "probe_name": s.probe_name,
                "target": s.target,
                "scan_type": s.scan_type,
                "gvm_status": s.gvm_status,
                "gvm_progress": s.gvm_progress,
                "created_at": s.created_at,
            }
            for s in scans
        ]
    }


async def get_scan_status(request: Request, scan_id: str):
    """
    Get current scan status.

    gvm_status and gvm_progress reflect the real values from GVM.
    """
    manager: ScanManager = request.app.state.scan_manager
    record = manager.get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanStatusResponse(
        scan_id=record.scan_id,
        probe_name=record.probe_name,
        gvm_status=record.gvm_status,
        gvm_progress=record.gvm_progress,
        target=record.target,
        scan_type=record.scan_type,
        created_at=record.created_at,
        started_at=record.started_at,
        completed_at=record.completed_at,
        error=record.error,
    )


async def get_scan_report(request: Request, scan_id: str):
    """
    Get the full XML report.

    Only available when gvm_status is 'Done'.
    """
    manager: ScanManager = request.app.state.scan_manager
    record = manager.get_scan(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail="Scan not found")

    if record.report_xml is None:
        raise HTTPException(
            status_code=409,
            detail=f"Report not available yet. Current status: {record.gvm_status}"
        )

    return ScanResultResponse(
        scan_id=record.scan_id,
        probe_name=record.probe_name,
        gvm_status=record.gvm_status,
        target=record.target,
        completed_at=record.completed_at,
        report_xml=record.report_xml,
        summary=record.summary,
        error=record.error,
    )
