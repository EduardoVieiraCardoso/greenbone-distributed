"""
Greenbone Central API - Models

Defines data models for scans, jobs, and probes.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field
import uuid


# =============================================================================
# Enums
# =============================================================================

class ScanType(str, Enum):
    """Tipo de scan"""
    FULL = "full"
    DIRECTED = "directed"


class JobStatus(str, Enum):
    """Status do job"""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ProbeStatus(str, Enum):
    """Status do probe"""
    ONLINE = "online"
    OFFLINE = "offline"
    BUSY = "busy"


# =============================================================================
# Request/Response Models
# =============================================================================

class ScanRequest(BaseModel):
    """Request para criar um scan"""
    target: str = Field(..., description="IP, hostname ou CIDR range", example="192.168.1.0/24")
    scan_type: ScanType = Field(..., description="Tipo de scan", example="full")
    ports: Optional[list[int]] = Field(None, description="Portas específicas (scan directed)", example=[22, 80, 443])
    probe_id: str = Field(..., description="ID do probe que executará", example="probe-sp-01")


class ScanResponse(BaseModel):
    """Response após criar scan"""
    job_id: str
    status: JobStatus
    message: str


class ScanStatusResponse(BaseModel):
    """Response com status do scan"""
    job_id: str
    status: JobStatus
    progress: int = 0
    target: str
    probe_id: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    summary: Optional[dict] = None
    error: Optional[str] = None


class ProbeRegisterRequest(BaseModel):
    """Request para registrar probe"""
    probe_id: str
    location: str
    endpoint: str = Field(..., description="URL do probe", example="http://10.0.0.5:8000")


class ProbeInfo(BaseModel):
    """Informações do probe"""
    probe_id: str
    location: str
    endpoint: str
    status: ProbeStatus = ProbeStatus.ONLINE
    last_seen: Optional[datetime] = None
    current_job: Optional[str] = None


class WebhookResult(BaseModel):
    """Resultado recebido do probe via webhook"""
    job_id: str
    probe_id: str
    status: JobStatus
    completed_at: datetime
    summary: Optional[dict] = None
    report_xml: Optional[str] = None  # base64 encoded
    error: Optional[str] = None


# =============================================================================
# Internal Models
# =============================================================================

class Job(BaseModel):
    """Job interno"""
    job_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    target: str
    scan_type: ScanType
    ports: Optional[list[int]] = None
    probe_id: str
    status: JobStatus = JobStatus.PENDING
    progress: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    summary: Optional[dict] = None
    report_xml: Optional[str] = None
    error: Optional[str] = None

    def to_probe_payload(self) -> dict:
        """Converte para payload enviado ao probe"""
        return {
            "job_id": self.job_id,
            "target": self.target,
            "scan_type": self.scan_type.value,
            "ports": self.ports
        }
