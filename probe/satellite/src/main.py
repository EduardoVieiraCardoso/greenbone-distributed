"""
Greenbone Satellite Controller

Interface entre o Central e o OpenVAS local.
Recebe jobs via NATS, executa scans no GVM, envia resultados via webhook.
"""

import asyncio
import base64
import json
import os
import signal
import sys
from datetime import datetime
from typing import Optional

import httpx
import nats
import structlog
from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from pydantic import BaseModel

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer()
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger()


class ScanJob(BaseModel):
    """Representa um job de scan recebido do central"""
    job_id: str
    type: str  # "full" ou "directed"
    target: str
    ports: Optional[list[int]] = None
    probe_id: Optional[str] = None
    status: str = "pending"


class ScanResult(BaseModel):
    """Resultado de um scan para enviar ao central"""
    job_id: str
    probe_id: str
    status: str
    completed_at: str
    report_xml: Optional[str] = None  # base64 encoded
    summary: dict


class GVMClient:
    """Cliente para interação com GVM via GMP (protocolo XML sobre TLS)"""

    def __init__(self):
        # immauss/openvas expõe gvmd na porta 9390 via TCP/TLS
        self.host = os.getenv("GVM_HOST", "openvas")
        self.port = int(os.getenv("GVM_PORT", "9390"))
        self.username = os.getenv("GVM_USERNAME", "admin")
        self.password = os.getenv("GVM_PASSWORD", "admin")
        self.timeout = int(os.getenv("GVM_TIMEOUT", "300"))

    def _connect(self):
        """Cria conexão TLS com GVM na porta 9390"""
        connection = TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=self.timeout
        )
        transform = EtreeTransform()
        return Gmp(connection=connection, transform=transform)

    def authenticate(self, gmp: Gmp):
        """Autentica no GVM"""
        gmp.authenticate(self.username, self.password)

    def create_target(self, gmp: Gmp, name: str, hosts: str, 
                      port_list_id: Optional[str] = None) -> str:
        """Cria um target no GVM"""
        log.info("creating_target", name=name, hosts=hosts)
        
        kwargs = {"name": name, "hosts": [hosts]}
        if port_list_id:
            kwargs["port_list_id"] = port_list_id
            
        response = gmp.create_target(**kwargs)
        target_id = response.get("id")
        log.info("target_created", target_id=target_id)
        return target_id

    def create_port_list(self, gmp: Gmp, name: str, ports: list[int]) -> str:
        """Cria uma port list customizada"""
        port_range = ",".join(f"T:{p}" for p in ports)
        log.info("creating_port_list", name=name, ports=ports)
        
        response = gmp.create_port_list(name=name, port_range=port_range)
        port_list_id = response.get("id")
        log.info("port_list_created", port_list_id=port_list_id)
        return port_list_id

    def get_scan_config_id(self, gmp: Gmp, config_name: str = "Full and fast") -> str:
        """Obtém ID de uma scan config existente"""
        configs = gmp.get_scan_configs()
        for config in configs.findall(".//config"):
            if config.find("name").text == config_name:
                return config.get("id")
        raise ValueError(f"Scan config '{config_name}' not found")

    def get_scanner_id(self, gmp: Gmp, scanner_name: str = "OpenVAS Default") -> str:
        """Obtém ID do scanner"""
        scanners = gmp.get_scanners()
        for scanner in scanners.findall(".//scanner"):
            if scanner.find("name").text == scanner_name:
                return scanner.get("id")
        raise ValueError(f"Scanner '{scanner_name}' not found")

    def create_task(self, gmp: Gmp, name: str, target_id: str, 
                    config_id: str, scanner_id: str) -> str:
        """Cria uma task de scan"""
        log.info("creating_task", name=name, target_id=target_id)
        
        response = gmp.create_task(
            name=name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        task_id = response.get("id")
        log.info("task_created", task_id=task_id)
        return task_id

    def start_task(self, gmp: Gmp, task_id: str) -> str:
        """Inicia uma task"""
        log.info("starting_task", task_id=task_id)
        response = gmp.start_task(task_id)
        report_id = response.find("report_id").text
        log.info("task_started", report_id=report_id)
        return report_id

    def get_task_status(self, gmp: Gmp, task_id: str) -> tuple[str, int]:
        """Obtém status de uma task"""
        task = gmp.get_task(task_id)
        status = task.find(".//status").text
        progress = int(task.find(".//progress").text or 0)
        return status, progress

    def get_report(self, gmp: Gmp, report_id: str, 
                   report_format: str = "XML") -> str:
        """Obtém relatório em formato especificado"""
        log.info("getting_report", report_id=report_id, format=report_format)
        
        # Obter ID do formato XML
        formats = gmp.get_report_formats()
        format_id = None
        for fmt in formats.findall(".//report_format"):
            if fmt.find("name").text == report_format:
                format_id = fmt.get("id")
                break
        
        if not format_id:
            raise ValueError(f"Report format '{report_format}' not found")
        
        response = gmp.get_report(
            report_id=report_id,
            report_format_id=format_id,
            ignore_pagination=True,
            details=True
        )
        
        # Extrair XML do relatório
        report_data = response.find(".//report")
        if report_data is not None:
            from xml.etree import ElementTree as ET
            return ET.tostring(report_data, encoding="unicode")
        return ""


class Satellite:
    """Controlador principal do Satellite"""

    def __init__(self):
        self.probe_id = os.getenv("PROBE_ID", "probe-unknown")
        self.probe_location = os.getenv("PROBE_LOCATION", "Unknown")
        self.nats_url = os.getenv("NATS_URL", "nats://localhost:4222")
        self.nats_token = os.getenv("NATS_TOKEN")
        self.central_webhook = os.getenv("CENTRAL_WEBHOOK")
        self.probe_token = os.getenv("PROBE_TOKEN")
        
        self.gvm = GVMClient()
        self.nc: Optional[nats.NATS] = None
        self.running = True
        self.current_job: Optional[ScanJob] = None

    async def connect_nats(self):
        """Conecta ao NATS server"""
        options = {
            "servers": [self.nats_url],
            "name": f"satellite-{self.probe_id}",
            "reconnect_time_wait": 2,
            "max_reconnect_attempts": -1,
        }
        
        if self.nats_token:
            options["token"] = self.nats_token
            
        self.nc = await nats.connect(**options)
        log.info("nats_connected", url=self.nats_url)

    async def register(self):
        """Registra probe no central"""
        msg = {
            "probe_id": self.probe_id,
            "location": self.probe_location,
            "status": "online"
        }
        
        try:
            response = await self.nc.request(
                "probes.register",
                json.dumps(msg).encode(),
                timeout=5
            )
            log.info("probe_registered", response=response.data.decode())
        except Exception as e:
            log.error("registration_failed", error=str(e))

    async def heartbeat_loop(self):
        """Envia heartbeats periódicos"""
        while self.running:
            try:
                status = "busy" if self.current_job else "online"
                msg = {
                    "probe_id": self.probe_id,
                    "status": status
                }
                await self.nc.publish("probes.status", json.dumps(msg).encode())
                log.debug("heartbeat_sent", status=status)
            except Exception as e:
                log.error("heartbeat_failed", error=str(e))
                
            await asyncio.sleep(30)

    async def job_handler(self, msg):
        """Processa jobs recebidos via NATS"""
        try:
            data = json.loads(msg.data.decode())
            job = ScanJob(**data)
            
            log.info("job_received", job_id=job.job_id, type=job.type, target=job.target)
            
            self.current_job = job
            
            # Executar scan
            result = await self.execute_scan(job)
            
            # Enviar resultado
            await self.send_result(result)
            
            self.current_job = None
            
        except Exception as e:
            log.error("job_processing_failed", error=str(e))
            self.current_job = None

    async def execute_scan(self, job: ScanJob) -> ScanResult:
        """Executa scan no GVM"""
        log.info("executing_scan", job_id=job.job_id)
        
        try:
            with self.gvm._connect() as gmp:
                self.gvm.authenticate(gmp)
                
                # Criar port list se direcionado
                port_list_id = None
                if job.type == "directed" and job.ports:
                    port_list_id = self.gvm.create_port_list(
                        gmp, 
                        f"job-{job.job_id}-ports",
                        job.ports
                    )
                
                # Criar target
                target_id = self.gvm.create_target(
                    gmp,
                    f"job-{job.job_id}-target",
                    job.target,
                    port_list_id
                )
                
                # Obter IDs necessários
                config_id = self.gvm.get_scan_config_id(gmp)
                scanner_id = self.gvm.get_scanner_id(gmp)
                
                # Criar e iniciar task
                task_id = self.gvm.create_task(
                    gmp,
                    f"job-{job.job_id}",
                    target_id,
                    config_id,
                    scanner_id
                )
                
                report_id = self.gvm.start_task(gmp, task_id)
                
                # Aguardar conclusão
                while True:
                    status, progress = self.gvm.get_task_status(gmp, task_id)
                    log.info("scan_progress", 
                             job_id=job.job_id, 
                             status=status, 
                             progress=progress)
                    
                    if status == "Done":
                        break
                    elif status in ["Stop Requested", "Stopped", "Error"]:
                        raise Exception(f"Scan failed with status: {status}")
                    
                    await asyncio.sleep(30)
                
                # Obter relatório
                report_xml = self.gvm.get_report(gmp, report_id)
                
                # TODO: Parse XML para summary
                summary = {
                    "hosts_scanned": 1,
                    "vulns_high": 0,
                    "vulns_medium": 0,
                    "vulns_low": 0
                }
                
                return ScanResult(
                    job_id=job.job_id,
                    probe_id=self.probe_id,
                    status="completed",
                    completed_at=datetime.utcnow().isoformat(),
                    report_xml=base64.b64encode(report_xml.encode()).decode(),
                    summary=summary
                )
                
        except Exception as e:
            log.error("scan_execution_failed", job_id=job.job_id, error=str(e))
            return ScanResult(
                job_id=job.job_id,
                probe_id=self.probe_id,
                status="failed",
                completed_at=datetime.utcnow().isoformat(),
                summary={"error": str(e)}
            )

    async def send_result(self, result: ScanResult):
        """Envia resultado para o central via webhook"""
        if not self.central_webhook:
            log.warn("no_webhook_configured")
            return
            
        log.info("sending_result", job_id=result.job_id)
        
        headers = {}
        if self.probe_token:
            headers["Authorization"] = f"Bearer {self.probe_token}"
        
        async with httpx.AsyncClient() as client:
            try:
                response = await client.post(
                    self.central_webhook,
                    json=result.model_dump(),
                    headers=headers,
                    timeout=30
                )
                log.info("result_sent", 
                         job_id=result.job_id, 
                         status_code=response.status_code)
            except Exception as e:
                log.error("result_send_failed", error=str(e))

    async def run(self):
        """Loop principal"""
        log.info("starting_satellite", 
                 probe_id=self.probe_id, 
                 location=self.probe_location)
        
        # Conectar ao NATS
        await self.connect_nats()
        
        # Registrar probe
        await self.register()
        
        # Subscrever a jobs para este probe
        await self.nc.subscribe(
            f"probes.{self.probe_id}.jobs",
            cb=self.job_handler
        )
        
        # Iniciar heartbeat
        heartbeat_task = asyncio.create_task(self.heartbeat_loop())
        
        log.info("satellite_ready", probe_id=self.probe_id)
        
        # Aguardar shutdown
        try:
            while self.running:
                await asyncio.sleep(1)
        finally:
            heartbeat_task.cancel()
            await self.nc.close()

    def shutdown(self):
        """Sinaliza shutdown"""
        log.info("shutting_down")
        self.running = False


async def main():
    satellite = Satellite()
    
    # Handler para shutdown graceful
    def signal_handler(sig, frame):
        satellite.shutdown()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    await satellite.run()


if __name__ == "__main__":
    asyncio.run(main())
