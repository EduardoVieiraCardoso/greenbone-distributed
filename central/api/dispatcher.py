"""
Greenbone Central API - Dispatcher

Sends scan jobs to probes via HTTP.
"""

import os
import httpx
import structlog
from datetime import datetime

from .models import Job, JobStatus, ProbeInfo
from . import db

log = structlog.get_logger()

# Timeout for sending jobs to probes
PROBE_TIMEOUT = int(os.getenv("PROBE_TIMEOUT", "30"))


async def dispatch_job(job: Job) -> bool:
    """
    Send job to the designated probe.
    
    Returns True if job was accepted by probe.
    """
    # Get probe info
    probe = db.get_probe(job.probe_id)
    
    if not probe:
        log.error("probe_not_found", probe_id=job.probe_id)
        job.status = JobStatus.FAILED
        job.error = f"Probe '{job.probe_id}' not found"
        db.save_job(job)
        return False
    
    # Build probe endpoint
    probe_url = f"{probe.endpoint.rstrip('/')}/jobs"
    
    log.info("dispatching_job",
             job_id=job.job_id,
             probe_id=job.probe_id,
             probe_url=probe_url,
             target=job.target)
    
    try:
        async with httpx.AsyncClient(timeout=PROBE_TIMEOUT) as client:
            response = await client.post(
                probe_url,
                json=job.to_probe_payload(),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in (200, 201, 202):
                log.info("job_dispatched",
                         job_id=job.job_id,
                         status_code=response.status_code)
                
                # Update job status
                job.status = JobStatus.QUEUED
                job.started_at = datetime.utcnow()
                db.save_job(job)
                
                # Update probe status
                db.update_probe_status(job.probe_id, db.ProbeStatus.BUSY, job.job_id)
                
                return True
            else:
                log.error("probe_rejected_job",
                         job_id=job.job_id,
                         status_code=response.status_code,
                         response=response.text[:200])
                
                job.status = JobStatus.FAILED
                job.error = f"Probe rejected: {response.status_code}"
                db.save_job(job)
                return False
                
    except httpx.TimeoutException:
        log.error("probe_timeout", job_id=job.job_id, probe_id=job.probe_id)
        job.status = JobStatus.FAILED
        job.error = "Probe timeout"
        db.save_job(job)
        return False
        
    except httpx.ConnectError as e:
        log.error("probe_connection_failed",
                 job_id=job.job_id,
                 probe_id=job.probe_id,
                 error=str(e))
        job.status = JobStatus.FAILED
        job.error = f"Cannot connect to probe: {e}"
        db.save_job(job)
        return False
        
    except Exception as e:
        log.error("dispatch_error",
                 job_id=job.job_id,
                 error=str(e))
        job.status = JobStatus.FAILED
        job.error = str(e)
        db.save_job(job)
        return False


async def check_probe_health(probe: ProbeInfo) -> bool:
    """Check if probe is healthy"""
    health_url = f"{probe.endpoint.rstrip('/')}/health"
    
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(health_url)
            return response.status_code == 200
    except Exception:
        return False
