"""
Probe API Models
"""

from typing import Optional
from pydantic import BaseModel


class JobRequest(BaseModel):
    """Job request from Central"""
    job_id: str
    target: str
    scan_type: str  # "full" or "directed"
    ports: Optional[list[int]] = None


class JobResponse(BaseModel):
    """Response after receiving job"""
    job_id: str
    status: str
    message: str


class HealthResponse(BaseModel):
    """Health check response"""
    status: str
    probe_id: str
    gvm_host: str


class StatusResponse(BaseModel):
    """Probe status response"""
    probe_id: str
    status: str  # "idle" or "busy"
    current_job: Optional[str] = None
    progress: int = 0
