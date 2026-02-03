"""
Greenbone Satellite Controller Package

Módulos:
- gvm_client: Interface com GVM via protocolo GMP
- nats_client: Comunicação com fila NATS
- main: Controller principal
"""

from .gvm_client import GVMClient, ScanStatus, VulnSummary
from .nats_client import NATSManager, ScanJob, ScanResult

__all__ = [
    "GVMClient",
    "ScanStatus", 
    "VulnSummary",
    "NATSManager",
    "ScanJob",
    "ScanResult"
]
