"""
Probe Satellite API

FastAPI application that receives scan jobs from Central.
"""

import os
import asyncio
import base64
from datetime import datetime
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks
import httpx
import structlog

from .gvm_client import GVMClient, ScanStatus
from .models import JobRequest, JobResponse, HealthResponse, StatusResponse

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
# State
# =============================================================================

class ProbeState:
    """Global probe state"""
    current_job: str = None
    current_progress: int = 0
    status: str = "idle"


state = ProbeState()


# =============================================================================
# App Lifecycle
# =============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup/shutdown"""
    log.info("probe_starting", probe_id=os.getenv("PROBE_ID", "unknown"))
    yield
    log.info("probe_shutdown")


# =============================================================================
# FastAPI App
# =============================================================================

app = FastAPI(
    title="Greenbone Probe API",
    description="Probe API for receiving and executing vulnerability scans",
    version="1.0.0",
    lifespan=lifespan
)


# =============================================================================
# Endpoints
# =============================================================================

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check"""
    return HealthResponse(
        status="healthy",
        probe_id=os.getenv("PROBE_ID", "unknown"),
        gvm_host=os.getenv("GVM_HOST", "localhost")
    )


@app.get("/status", response_model=StatusResponse)
async def status():
    """Current probe status"""
    return StatusResponse(
        probe_id=os.getenv("PROBE_ID", "unknown"),
        status=state.status,
        current_job=state.current_job,
        progress=state.current_progress
    )


@app.post("/jobs", response_model=JobResponse)
async def receive_job(request: JobRequest, background_tasks: BackgroundTasks):
    """
    Receive a scan job from Central API.
    
    The scan is executed in the background.
    """
    log.info("job_received",
             job_id=request.job_id,
             target=request.target,
             scan_type=request.scan_type)
    
    # Check if busy
    if state.status == "busy":
        raise HTTPException(
            status_code=409,
            detail=f"Probe busy with job {state.current_job}"
        )
    
    # Mark as busy
    state.status = "busy"
    state.current_job = request.job_id
    state.current_progress = 0
    
    # Execute scan in background
    background_tasks.add_task(execute_scan, request)
    
    return JobResponse(
        job_id=request.job_id,
        status="accepted",
        message="Scan started"
    )


# =============================================================================
# Scan Execution
# =============================================================================

async def execute_scan(request: JobRequest):
    """Execute scan and send result to webhook"""
    log.info("scan_starting", job_id=request.job_id, target=request.target)
    
    webhook_url = os.getenv("CENTRAL_WEBHOOK")
    probe_id = os.getenv("PROBE_ID", "unknown")
    poll_interval = int(os.getenv("SCAN_POLL_INTERVAL", "30"))
    
    result = {
        "job_id": request.job_id,
        "probe_id": probe_id,
        "status": "failed",
        "completed_at": datetime.utcnow().isoformat(),
        "summary": None,
        "report_xml": None,
        "error": None
    }
    
    try:
        with GVMClient() as gvm:
            # Create port list if directed scan
            port_list_id = None
            if request.scan_type == "directed" and request.ports:
                port_list_id = gvm.create_port_list(
                    name=f"job-{request.job_id}-ports",
                    ports=request.ports
                )
            
            # Create target
            target_id = gvm.create_target(
                name=f"job-{request.job_id}-target",
                hosts=request.target,
                port_list_id=port_list_id
            )
            
            # Create task
            task_id = gvm.create_task(
                name=f"job-{request.job_id}",
                target_id=target_id
            )
            
            # Start scan
            report_id = gvm.start_task(task_id)
            
            log.info("scan_running",
                     job_id=request.job_id,
                     task_id=task_id,
                     report_id=report_id)
            
            # Poll for completion
            while True:
                scan_status, progress = gvm.get_task_status(task_id)
                state.current_progress = progress
                
                log.info("scan_progress",
                         job_id=request.job_id,
                         status=scan_status.value,
                         progress=progress)
                
                if scan_status == ScanStatus.DONE:
                    break
                elif scan_status in [ScanStatus.STOPPED, ScanStatus.ERROR]:
                    raise Exception(f"Scan failed: {scan_status.value}")
                
                await asyncio.sleep(poll_interval)
            
            # Get report
            log.info("collecting_report", job_id=request.job_id)
            report_xml = gvm.get_report_xml(report_id)
            summary = gvm.parse_report_summary(report_xml)
            
            result["status"] = "completed"
            result["completed_at"] = datetime.utcnow().isoformat()
            result["summary"] = {
                "hosts_scanned": summary.hosts_scanned,
                "vulns_high": summary.vulns_high,
                "vulns_medium": summary.vulns_medium,
                "vulns_low": summary.vulns_low,
                "vulns_log": summary.vulns_log
            }
            result["report_xml"] = base64.b64encode(report_xml.encode()).decode()
            
            log.info("scan_completed",
                     job_id=request.job_id,
                     summary=result["summary"])
            
    except Exception as e:
        log.error("scan_failed", job_id=request.job_id, error=str(e))
        result["status"] = "failed"
        result["error"] = str(e)
    
    finally:
        # Reset state
        state.status = "idle"
        state.current_job = None
        state.current_progress = 0
    
    # Send result to webhook
    if webhook_url:
        await send_to_webhook(webhook_url, result)


async def send_to_webhook(url: str, result: dict):
    """Send result to Central webhook"""
    log.info("sending_webhook", job_id=result["job_id"], url=url)
    
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.post(url, json=result)
            
            log.info("webhook_sent",
                     job_id=result["job_id"],
                     status_code=response.status_code)
            
    except Exception as e:
        log.error("webhook_failed",
                 job_id=result["job_id"],
                 error=str(e))


# =============================================================================
# Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn
    
    port = int(os.getenv("PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port)
