"""
NATS Client - Comunicação com a fila de mensagens

Gerencia conexão com NATS, subscrição de jobs, e publicação de status/resultados.
"""

import asyncio
import json
import os
from typing import Callable, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime

import nats
from nats.aio.client import Client as NATSClient
from nats.aio.msg import Msg
import structlog

log = structlog.get_logger()


# Subjects NATS
class Subjects:
    """Definição de todos os subjects NATS usados"""
    PROBES_REGISTER = "probes.register"
    PROBES_STATUS = "probes.status"
    SCANS_COMPLETED = "scans.completed"
    
    @staticmethod
    def probe_jobs(probe_id: str) -> str:
        """Subject para jobs de um probe específico"""
        return f"probes.{probe_id}.jobs"


@dataclass
class ProbeInfo:
    """Informações do probe para registro"""
    probe_id: str
    location: str
    status: str = "online"
    current_job: Optional[str] = None


@dataclass
class ScanJob:
    """Job de scan recebido da fila"""
    job_id: str
    type: str  # "full" ou "directed"
    target: str
    ports: Optional[list[int]] = None
    probe_id: Optional[str] = None
    status: str = "pending"
    created_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict) -> "ScanJob":
        return cls(
            job_id=data.get("job_id", ""),
            type=data.get("type", "full"),
            target=data.get("target", ""),
            ports=data.get("ports"),
            probe_id=data.get("probe_id"),
            status=data.get("status", "pending"),
            created_at=data.get("created_at")
        )


@dataclass
class ScanResult:
    """Resultado de scan para enviar ao central"""
    job_id: str
    probe_id: str
    status: str
    completed_at: str
    report_xml: Optional[str] = None  # base64 encoded
    summary: Optional[dict] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v is not None}


class NATSManager:
    """
    Gerenciador de conexão NATS.
    
    Handles:
    - Conexão/reconexão automática
    - Registro do probe
    - Heartbeat periódico
    - Subscrição a jobs
    - Publicação de resultados
    """

    def __init__(
        self,
        probe_id: str,
        probe_location: str = "Unknown",
        nats_url: Optional[str] = None,
        nats_token: Optional[str] = None
    ):
        self.probe_id = probe_id
        self.probe_location = probe_location
        self.nats_url = nats_url or os.getenv("NATS_URL", "nats://localhost:4222")
        self.nats_token = nats_token or os.getenv("NATS_TOKEN")
        
        self._nc: Optional[NATSClient] = None
        self._running = False
        self._heartbeat_task: Optional[asyncio.Task] = None
        self._current_job: Optional[str] = None
        self._job_handler: Optional[Callable] = None

    async def connect(self):
        """Conecta ao NATS server"""
        log.info("nats_connecting", url=self.nats_url, probe_id=self.probe_id)
        
        options = {
            "servers": [self.nats_url],
            "name": f"satellite-{self.probe_id}",
            "reconnect_time_wait": 2,
            "max_reconnect_attempts": -1,
            "disconnected_cb": self._on_disconnect,
            "reconnected_cb": self._on_reconnect,
            "error_cb": self._on_error,
        }
        
        if self.nats_token:
            options["token"] = self.nats_token
        
        self._nc = await nats.connect(**options)
        self._running = True
        
        log.info("nats_connected", url=self.nats_url)

    async def disconnect(self):
        """Desconecta do NATS"""
        self._running = False
        
        if self._heartbeat_task:
            self._heartbeat_task.cancel()
            try:
                await self._heartbeat_task
            except asyncio.CancelledError:
                pass
        
        if self._nc:
            await self._nc.close()
            self._nc = None
        
        log.info("nats_disconnected")

    async def _on_disconnect(self):
        log.warning("nats_disconnected_unexpectedly")

    async def _on_reconnect(self):
        log.info("nats_reconnected")
        # Re-registrar após reconexão
        await self.register()

    async def _on_error(self, e):
        log.error("nats_error", error=str(e))

    # =========================================================================
    # Probe Registration & Heartbeat
    # =========================================================================

    async def register(self) -> bool:
        """
        Registra o probe no orchestrator central.
        
        Returns:
            True se registro foi aceito
        """
        if not self._nc:
            raise RuntimeError("Not connected to NATS")
        
        info = ProbeInfo(
            probe_id=self.probe_id,
            location=self.probe_location,
            status="online"
        )
        
        log.info("probe_registering", probe_id=self.probe_id)
        
        try:
            response = await self._nc.request(
                Subjects.PROBES_REGISTER,
                json.dumps(asdict(info)).encode(),
                timeout=10
            )
            
            result = json.loads(response.data.decode())
            log.info("probe_registered", response=result)
            return result.get("status") == "registered"
            
        except asyncio.TimeoutError:
            log.error("probe_registration_timeout")
            return False
        except Exception as e:
            log.error("probe_registration_failed", error=str(e))
            return False

    async def start_heartbeat(self, interval: int = 30):
        """Inicia loop de heartbeat"""
        self._heartbeat_task = asyncio.create_task(
            self._heartbeat_loop(interval)
        )

    async def _heartbeat_loop(self, interval: int):
        """Loop de heartbeat periódico"""
        while self._running:
            try:
                status = "busy" if self._current_job else "online"
                
                msg = {
                    "probe_id": self.probe_id,
                    "status": status,
                    "current_job": self._current_job,
                    "timestamp": datetime.utcnow().isoformat()
                }
                
                await self._nc.publish(
                    Subjects.PROBES_STATUS,
                    json.dumps(msg).encode()
                )
                
                log.debug("heartbeat_sent", status=status)
                
            except Exception as e:
                log.error("heartbeat_failed", error=str(e))
            
            await asyncio.sleep(interval)

    def set_current_job(self, job_id: Optional[str]):
        """Atualiza job atual (para heartbeat)"""
        self._current_job = job_id

    # =========================================================================
    # Job Subscription
    # =========================================================================

    async def subscribe_jobs(self, handler: Callable[[ScanJob], Any]):
        """
        Subscreve para receber jobs de scan.
        
        Args:
            handler: Função async que processa ScanJob
        """
        if not self._nc:
            raise RuntimeError("Not connected to NATS")
        
        self._job_handler = handler
        subject = Subjects.probe_jobs(self.probe_id)
        
        await self._nc.subscribe(subject, cb=self._on_job_message)
        log.info("subscribed_to_jobs", subject=subject)

    async def _on_job_message(self, msg: Msg):
        """Callback interno para mensagens de job"""
        try:
            data = json.loads(msg.data.decode())
            job = ScanJob.from_dict(data)
            
            log.info("job_received", 
                     job_id=job.job_id, 
                     type=job.type, 
                     target=job.target)
            
            self.set_current_job(job.job_id)
            
            if self._job_handler:
                await self._job_handler(job)
            
            self.set_current_job(None)
            
        except json.JSONDecodeError as e:
            log.error("job_parse_error", error=str(e))
        except Exception as e:
            log.error("job_handler_error", error=str(e))
            self.set_current_job(None)

    # =========================================================================
    # Result Publishing
    # =========================================================================

    async def publish_result(self, result: ScanResult):
        """Publica resultado de scan no NATS"""
        if not self._nc:
            raise RuntimeError("Not connected to NATS")
        
        log.info("publishing_result", job_id=result.job_id, status=result.status)
        
        await self._nc.publish(
            Subjects.SCANS_COMPLETED,
            json.dumps(result.to_dict()).encode()
        )

    async def publish_status(self, job_id: str, status: str, progress: int = 0):
        """Publica atualização de status de um scan"""
        if not self._nc:
            return
        
        msg = {
            "job_id": job_id,
            "probe_id": self.probe_id,
            "status": status,
            "progress": progress,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        await self._nc.publish(
            f"scans.{job_id}.status",
            json.dumps(msg).encode()
        )
