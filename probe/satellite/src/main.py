"""
Greenbone Satellite Controller

Serviço que roda nos probes remotos:
1. Conecta no NATS central
2. Aguarda jobs de scan
3. Executa scans no GVM local
4. Envia resultados de volta

Fluxo:
  NATS (job) -> Satellite -> GVM (scan) -> Satellite -> NATS (result) + Webhook
"""

import asyncio
import base64
import os
import signal
import sys
from datetime import datetime
from typing import Optional

import httpx
import structlog

from .gvm_client import GVMClient, ScanStatus, VulnSummary
from .nats_client import NATSManager, ScanJob, ScanResult

# Configure logging
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
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


class SatelliteController:
    """
    Controlador principal do Satellite.
    
    Orquestra a comunicação entre NATS (fila) e GVM (scanner).
    """

    def __init__(self):
        # Config do probe
        self.probe_id = os.getenv("PROBE_ID", "probe-unknown")
        self.probe_location = os.getenv("PROBE_LOCATION", "Unknown")
        
        # Webhook para enviar resultados
        self.webhook_url = os.getenv("CENTRAL_WEBHOOK")
        self.probe_token = os.getenv("PROBE_TOKEN")
        
        # Intervalo de polling do status do scan (segundos)
        self.poll_interval = int(os.getenv("SCAN_POLL_INTERVAL", "30"))
        
        # Clientes
        self.nats = NATSManager(
            probe_id=self.probe_id,
            probe_location=self.probe_location
        )
        self.gvm = GVMClient()
        
        # Estado
        self._running = True
        self._current_scan: Optional[dict] = None

    async def start(self):
        """Inicia o Satellite Controller"""
        log.info("satellite_starting", 
                 probe_id=self.probe_id, 
                 location=self.probe_location)
        
        # Conectar ao NATS
        await self.nats.connect()
        
        # Registrar probe
        registered = await self.nats.register()
        if not registered:
            log.warning("probe_registration_failed_continuing")
        
        # Iniciar heartbeat
        await self.nats.start_heartbeat(interval=30)
        
        # Subscrever a jobs
        await self.nats.subscribe_jobs(self.handle_job)
        
        log.info("satellite_ready", probe_id=self.probe_id)
        
        # Loop principal
        while self._running:
            await asyncio.sleep(1)
        
        # Cleanup
        await self.nats.disconnect()
        log.info("satellite_stopped")

    def stop(self):
        """Para o Satellite gracefully"""
        log.info("satellite_stopping")
        self._running = False

    async def handle_job(self, job: ScanJob):
        """
        Processa um job de scan recebido da fila.
        
        1. Conecta no GVM
        2. Cria target e task
        3. Inicia scan
        4. Monitora progresso
        5. Coleta resultado
        6. Envia para central
        """
        log.info("processing_job", 
                 job_id=job.job_id, 
                 type=job.type, 
                 target=job.target)
        
        result = await self.execute_scan(job)
        
        # Publicar resultado no NATS
        await self.nats.publish_result(result)
        
        # Enviar para webhook se configurado
        if self.webhook_url:
            await self.send_to_webhook(result)
        
        log.info("job_completed", 
                 job_id=job.job_id, 
                 status=result.status)

    async def execute_scan(self, job: ScanJob) -> ScanResult:
        """
        Executa o scan no GVM e retorna resultado.
        """
        task_id = None
        report_id = None
        port_list_id = None
        
        try:
            # Conectar ao GVM
            log.info("connecting_to_gvm", job_id=job.job_id)
            
            with self.gvm as gvm:
                # Criar port list se scan direcionado
                if job.type == "directed" and job.ports:
                    port_list_id = gvm.create_port_list(
                        name=f"job-{job.job_id}-ports",
                        ports=job.ports
                    )
                
                # Criar target
                target_id = gvm.create_target(
                    name=f"job-{job.job_id}-target",
                    hosts=job.target,
                    port_list_id=port_list_id
                )
                
                # Criar task
                task_id = gvm.create_task(
                    name=f"job-{job.job_id}",
                    target_id=target_id
                )
                
                # Iniciar scan
                report_id = gvm.start_task(task_id)
                
                # Monitorar progresso
                log.info("scan_started", 
                         job_id=job.job_id, 
                         task_id=task_id,
                         report_id=report_id)
                
                while True:
                    status, progress = gvm.get_task_status(task_id)
                    
                    log.info("scan_progress",
                             job_id=job.job_id,
                             status=status.value,
                             progress=progress)
                    
                    # Publicar status update
                    await self.nats.publish_status(
                        job_id=job.job_id,
                        status=status.value,
                        progress=progress
                    )
                    
                    if status == ScanStatus.DONE:
                        break
                    elif status in [ScanStatus.STOPPED, ScanStatus.ERROR, ScanStatus.STOP_REQUESTED]:
                        raise Exception(f"Scan failed with status: {status.value}")
                    
                    await asyncio.sleep(self.poll_interval)
                
                # Coletar relatório
                log.info("collecting_report", job_id=job.job_id)
                report_xml = gvm.get_report_xml(report_id)
                
                # Parsear summary
                summary = gvm.parse_report_summary(report_xml)
                
                log.info("scan_completed",
                         job_id=job.job_id,
                         hosts=summary.hosts_scanned,
                         high=summary.vulns_high,
                         medium=summary.vulns_medium,
                         low=summary.vulns_low)
                
                return ScanResult(
                    job_id=job.job_id,
                    probe_id=self.probe_id,
                    status="completed",
                    completed_at=datetime.utcnow().isoformat(),
                    report_xml=base64.b64encode(report_xml.encode()).decode(),
                    summary={
                        "hosts_scanned": summary.hosts_scanned,
                        "vulns_high": summary.vulns_high,
                        "vulns_medium": summary.vulns_medium,
                        "vulns_low": summary.vulns_low,
                        "vulns_log": summary.vulns_log
                    }
                )
                
        except Exception as e:
            log.error("scan_execution_failed", 
                      job_id=job.job_id, 
                      error=str(e))
            
            return ScanResult(
                job_id=job.job_id,
                probe_id=self.probe_id,
                status="failed",
                completed_at=datetime.utcnow().isoformat(),
                error=str(e),
                summary={}
            )

    async def send_to_webhook(self, result: ScanResult):
        """Envia resultado para o webhook central"""
        log.info("sending_to_webhook", 
                 job_id=result.job_id, 
                 url=self.webhook_url)
        
        headers = {"Content-Type": "application/json"}
        if self.probe_token:
            headers["Authorization"] = f"Bearer {self.probe_token}"
        
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                response = await client.post(
                    self.webhook_url,
                    json=result.to_dict(),
                    headers=headers
                )
                
                log.info("webhook_response",
                         job_id=result.job_id,
                         status_code=response.status_code)
                
                if response.status_code >= 400:
                    log.warning("webhook_error", 
                                status=response.status_code,
                                body=response.text[:200])
                                
        except Exception as e:
            log.error("webhook_send_failed", error=str(e))


async def main():
    """Entry point"""
    satellite = SatelliteController()
    
    # Setup signal handlers
    loop = asyncio.get_event_loop()
    
    def signal_handler():
        satellite.stop()
    
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, signal_handler)
    
    try:
        await satellite.start()
    except KeyboardInterrupt:
        satellite.stop()


if __name__ == "__main__":
    asyncio.run(main())
