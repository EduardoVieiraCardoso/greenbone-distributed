"""
Data models for Scan Hub.

All scan statuses reflect real Greenbone/GVM statuses — nothing is invented.
"""

import ipaddress
import re
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, field_validator

_HOSTNAME_RE = re.compile(
    r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
)


# =============================================================================
# Enums — mapped directly from GVM task statuses
# =============================================================================

class GVMScanStatus(str, Enum):
    """
    Real GVM task statuses as returned by the GMP protocol.
    
    These are the actual values from gvmd get_tasks response <status> field.
    Reference: https://docs.greenbone.net/API/GMP/gmp-22.04.html
    """
    NEW = "New"
    REQUESTED = "Requested"
    QUEUED = "Queued"
    RUNNING = "Running"
    STOP_REQUESTED = "Stop Requested"
    STOPPED = "Stopped"
    DONE = "Done"
    DELETE_REQUESTED = "Delete Requested"
    ULTIMATE_DELETE_REQUESTED = "Ultimate Delete Requested"
    INTERRUPTED = "Interrupted"


class ScanType(str, Enum):
    FULL = "full"
    DIRECTED = "directed"


# =============================================================================
# Request / Response Models
# =============================================================================

class ScanRequest(BaseModel):
    """Request to create a scan."""
    target: str = Field(..., description="IP, hostname or CIDR range")
    scan_type: ScanType = Field(ScanType.FULL, description="Scan type")
    ports: Optional[list[int]] = Field(None, description="Specific ports (for directed scan)")
    probe_name: Optional[str] = Field(None, description="Target probe (auto-selects least-busy if omitted)")
    name: Optional[str] = Field(None, description="Friendly name for GVM dashboard (defaults to target)")

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("target cannot be empty")
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            pass
        try:
            net = ipaddress.ip_network(v, strict=False)
            if net.prefixlen == 0:
                raise ValueError("target /0 network is not allowed")
            return v
        except ValueError as e:
            if "/0" in str(e) or "not allowed" in str(e):
                raise
        if _HOSTNAME_RE.match(v) and len(v) <= 253:
            return v
        raise ValueError(
            f"Invalid target '{v}'. Must be an IP address, CIDR range, or hostname."
        )

    @field_validator("ports")
    @classmethod
    def validate_ports(cls, v: Optional[list[int]]) -> Optional[list[int]]:
        if v is None:
            return v
        if not v:
            raise ValueError("ports list cannot be empty")
        for port in v:
            if not (1 <= port <= 65535):
                raise ValueError(f"Port {port} out of range (1-65535)")
        return v


class ScanStatusResponse(BaseModel):
    """Current scan status — reflects real GVM state."""
    scan_id: str
    probe_name: str = Field(..., description="Probe that is running this scan")
    gvm_status: str = Field(..., description="Real GVM task status")
    gvm_progress: int = Field(..., description="Real GVM progress percentage (0-100)")
    target: str
    scan_type: ScanType
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None


class ScanResultResponse(BaseModel):
    """Scan result with full XML report."""
    scan_id: str
    probe_name: str
    gvm_status: str
    target: str
    completed_at: Optional[datetime] = None
    report_xml: Optional[str] = Field(None, description="Full XML report from GVM")
    summary: Optional[dict] = None
    error: Optional[str] = None


class ScanCreatedResponse(BaseModel):
    """Response after creating a scan."""
    scan_id: str
    probe_name: str
    message: str


# =============================================================================
# Internal Models
# =============================================================================

class ScanRecord(BaseModel):
    """Internal scan tracking record."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    probe_name: str = "default"
    name: Optional[str] = None
    target: str
    scan_type: ScanType
    ports: Optional[list[int]] = None
    external_target_id: Optional[str] = None

    # GVM resource IDs
    gvm_target_id: Optional[str] = None
    gvm_task_id: Optional[str] = None
    gvm_report_id: Optional[str] = None
    gvm_port_list_id: Optional[str] = None

    # Status — always from GVM
    gvm_status: str = GVMScanStatus.NEW.value
    gvm_progress: int = 0

    # Timestamps
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None

    # Results
    report_xml: Optional[str] = None
    summary: Optional[dict] = None
    error: Optional[str] = None
