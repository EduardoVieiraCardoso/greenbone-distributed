"""
Greenbone Central API

FastAPI application for managing vulnerability scans.
"""

import os
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import structlog

from .models import (
    ScanRequest, ScanResponse, ScanStatusResponse,
    ProbeRegisterRequest, ProbeInfo, ProbeStatus,
    WebhookResult, Job, JobStatus
)
from . import db
from .dispatcher import dispatch_job

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer() if os.getenv("LOG_FORMAT") == "console" 
            else structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger()


# =============================================================================
# App Lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown"""
    log.info("api_starting")
    db.init_db()
    log.info("database_initialized")
    yield
    log.info("api_shutdown")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="Greenbone Central API",
    description="API for distributed vulnerability scanning",
    version="1.0.0",
    lifespan=lifespan
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Health Check
# =============================================================================

@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


# =============================================================================
# Scan Endpoints
# =============================================================================

@app.post("/api/scans", response_model=ScanResponse)
async def create_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """
    Create a new scan job.
    
    The scan will be dispatched to the specified probe.
    """
    log.info("scan_requested",
             target=request.target,
             scan_type=request.scan_type,
             probe_id=request.probe_id)
    
    # Validate probe exists
    probe = db.get_probe(request.probe_id)
    if not probe:
        raise HTTPException(
            status_code=400,
            detail=f"Probe '{request.probe_id}' not registered"
        )
    
    # Validate directed scan has ports
    if request.scan_type == "directed" and not request.ports:
        raise HTTPException(
            status_code=400,
            detail="Directed scan requires 'ports' field"
        )
    
    # Create job
    job = Job(
        target=request.target,
        scan_type=request.scan_type,
        ports=request.ports,
        probe_id=request.probe_id
    )
    
    # Save to DB
    db.save_job(job)
    
    # Dispatch to probe in background
    background_tasks.add_task(dispatch_job, job)
    
    log.info("scan_created", job_id=job.job_id)
    
    return ScanResponse(
        job_id=job.job_id,
        status=JobStatus.PENDING,
        message="Scan queued for execution"
    )


@app.get("/api/scans/{job_id}", response_model=ScanStatusResponse)
async def get_scan_status(job_id: str):
    """Get scan job status"""
    job = db.get_job(job_id)
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    return ScanStatusResponse(
        job_id=job.job_id,
        status=job.status,
        progress=job.progress,
        target=job.target,
        probe_id=job.probe_id,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        summary=job.summary,
        error=job.error
    )


@app.get("/api/scans")
async def list_scans(status: str = None, limit: int = 100):
    """List scan jobs"""
    job_status = JobStatus(status) if status else None
    jobs = db.list_jobs(status=job_status, limit=limit)
    
    return {
        "total": len(jobs),
        "jobs": [
            {
                "job_id": j.job_id,
                "target": j.target,
                "status": j.status,
                "probe_id": j.probe_id,
                "created_at": j.created_at
            }
            for j in jobs
        ]
    }


# =============================================================================
# Probe Endpoints
# =============================================================================

@app.post("/api/probes/register")
async def register_probe(request: ProbeRegisterRequest):
    """Register a probe"""
    log.info("probe_registering",
             probe_id=request.probe_id,
             location=request.location,
             endpoint=request.endpoint)
    
    probe = ProbeInfo(
        probe_id=request.probe_id,
        location=request.location,
        endpoint=request.endpoint,
        status=ProbeStatus.ONLINE,
        last_seen=datetime.utcnow()
    )
    
    db.save_probe(probe)
    
    log.info("probe_registered", probe_id=request.probe_id)
    
    return {"status": "registered", "probe_id": request.probe_id}


@app.get("/api/probes")
async def list_probes():
    """List all registered probes"""
    probes = db.list_probes()
    
    return {
        "total": len(probes),
        "probes": [
            {
                "probe_id": p.probe_id,
                "location": p.location,
                "endpoint": p.endpoint,
                "status": p.status,
                "last_seen": p.last_seen
            }
            for p in probes
        ]
    }


# =============================================================================
# Webhook Endpoint
# =============================================================================

@app.post("/webhook/results")
async def receive_results(result: WebhookResult):
    """
    Receive scan results from probe.
    
    This is called by the probe when a scan completes.
    """
    log.info("webhook_received",
             job_id=result.job_id,
             probe_id=result.probe_id,
             status=result.status)
    
    # Get existing job
    job = db.get_job(result.job_id)
    if not job:
        log.warning("webhook_unknown_job", job_id=result.job_id)
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Update job
    db.update_job_status(
        job_id=result.job_id,
        status=result.status,
        completed_at=result.completed_at,
        summary=result.summary,
        report_xml=result.report_xml,
        error=result.error
    )
    
    # Update probe status
    db.update_probe_status(result.probe_id, ProbeStatus.ONLINE, None)
    
    log.info("job_completed",
             job_id=result.job_id,
             status=result.status,
             summary=result.summary)
    
    return {"status": "received"}


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", "8080"))
    uvicorn.run(app, host="0.0.0.0", port=port)
