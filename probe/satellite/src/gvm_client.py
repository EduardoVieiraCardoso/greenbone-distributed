"""
GVM Client - Interface com Greenbone Vulnerability Manager via GMP

Este módulo encapsula toda a comunicação com o GVM usando o protocolo GMP.
"""

import os
import ssl
from typing import Optional
from xml.etree import ElementTree as ET
from dataclasses import dataclass
from enum import Enum

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
import structlog

log = structlog.get_logger()


class ScanStatus(str, Enum):
    """Status possíveis de um scan"""
    NEW = "New"
    REQUESTED = "Requested"
    QUEUED = "Queued"
    RUNNING = "Running"
    STOP_REQUESTED = "Stop Requested"
    STOPPED = "Stopped"
    DONE = "Done"
    ERROR = "Error"


@dataclass
class ScanConfig:
    """Configuração de scan disponível no GVM"""
    id: str
    name: str


@dataclass
class Scanner:
    """Scanner disponível no GVM"""
    id: str
    name: str


@dataclass
class PortList:
    """Port list no GVM"""
    id: str
    name: str


@dataclass
class Target:
    """Target criado no GVM"""
    id: str
    name: str
    hosts: str


@dataclass
class Task:
    """Task de scan no GVM"""
    id: str
    name: str
    status: ScanStatus
    progress: int


@dataclass
class VulnSummary:
    """Resumo de vulnerabilidades encontradas"""
    hosts_scanned: int = 0
    vulns_high: int = 0
    vulns_medium: int = 0
    vulns_low: int = 0
    vulns_log: int = 0


class GVMClient:
    """
    Cliente para comunicação com GVM via GMP (Greenbone Management Protocol).
    
    O GMP é um protocolo XML sobre TLS que permite controle total do GVM.
    A imagem immauss/openvas expõe o gvmd na porta 9390.
    """

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        timeout: Optional[int] = None
    ):
        self.host = host or os.getenv("GVM_HOST", "localhost")
        self.port = port or int(os.getenv("GVM_PORT", "9390"))
        self.username = username or os.getenv("GVM_USERNAME", "admin")
        self.password = password or os.getenv("GVM_PASSWORD", "admin")
        self.timeout = timeout or int(os.getenv("GVM_TIMEOUT", "300"))
        
        self._gmp: Optional[Gmp] = None
        self._connection: Optional[TLSConnection] = None

    def connect(self) -> "GVMClient":
        """Estabelece conexão TLS com o GVM"""
        log.info("gvm_connecting", host=self.host, port=self.port)
        
        self._connection = TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=self.timeout
        )
        
        transform = EtreeTransform()
        self._gmp = Gmp(connection=self._connection, transform=transform)
        
        # Autenticar
        self._gmp.authenticate(self.username, self.password)
        
        log.info("gvm_connected", host=self.host)
        return self

    def disconnect(self):
        """Fecha conexão com o GVM"""
        if self._connection:
            try:
                self._connection.disconnect()
            except Exception:
                pass
        self._gmp = None
        self._connection = None

    def __enter__(self):
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()

    @property
    def gmp(self) -> Gmp:
        """Retorna instância GMP ativa"""
        if not self._gmp:
            raise RuntimeError("GVM not connected. Call connect() first.")
        return self._gmp

    # =========================================================================
    # Scan Configs
    # =========================================================================
    
    def get_scan_configs(self) -> list[ScanConfig]:
        """Lista configurações de scan disponíveis"""
        response = self.gmp.get_scan_configs()
        configs = []
        for config in response.findall(".//config"):
            configs.append(ScanConfig(
                id=config.get("id"),
                name=config.find("name").text
            ))
        return configs

    def get_scan_config_id(self, name: str = "Full and fast") -> str:
        """Obtém ID de uma scan config pelo nome"""
        configs = self.get_scan_configs()
        for config in configs:
            if config.name == name:
                return config.id
        raise ValueError(f"Scan config '{name}' not found. Available: {[c.name for c in configs]}")

    # =========================================================================
    # Scanners
    # =========================================================================
    
    def get_scanners(self) -> list[Scanner]:
        """Lista scanners disponíveis"""
        response = self.gmp.get_scanners()
        scanners = []
        for scanner in response.findall(".//scanner"):
            scanners.append(Scanner(
                id=scanner.get("id"),
                name=scanner.find("name").text
            ))
        return scanners

    def get_scanner_id(self, name: str = "OpenVAS Default") -> str:
        """Obtém ID de um scanner pelo nome"""
        scanners = self.get_scanners()
        for scanner in scanners:
            if scanner.name == name:
                return scanner.id
        raise ValueError(f"Scanner '{name}' not found. Available: {[s.name for s in scanners]}")

    # =========================================================================
    # Port Lists
    # =========================================================================
    
    def get_port_lists(self) -> list[PortList]:
        """Lista port lists disponíveis"""
        response = self.gmp.get_port_lists()
        port_lists = []
        for pl in response.findall(".//port_list"):
            port_lists.append(PortList(
                id=pl.get("id"),
                name=pl.find("name").text
            ))
        return port_lists

    def create_port_list(self, name: str, ports: list[int]) -> str:
        """
        Cria uma port list customizada.
        
        Args:
            name: Nome da port list
            ports: Lista de portas (ex: [22, 80, 443])
            
        Returns:
            ID da port list criada
        """
        # Formato: T:22,T:80,T:443 (T = TCP)
        port_range = ",".join(f"T:{p}" for p in ports)
        
        log.info("creating_port_list", name=name, ports=ports)
        response = self.gmp.create_port_list(name=name, port_range=port_range)
        
        port_list_id = response.get("id")
        log.info("port_list_created", id=port_list_id)
        return port_list_id

    def delete_port_list(self, port_list_id: str):
        """Remove uma port list"""
        self.gmp.delete_port_list(port_list_id)

    # =========================================================================
    # Targets
    # =========================================================================
    
    def create_target(
        self,
        name: str,
        hosts: str,
        port_list_id: Optional[str] = None
    ) -> str:
        """
        Cria um target (alvo) para scan.
        
        Args:
            name: Nome do target
            hosts: IP, range ou hostname (ex: "192.168.1.0/24", "10.0.0.5")
            port_list_id: ID da port list (opcional, usa default se None)
            
        Returns:
            ID do target criado
        """
        log.info("creating_target", name=name, hosts=hosts)
        
        kwargs = {"name": name, "hosts": [hosts]}
        if port_list_id:
            kwargs["port_list_id"] = port_list_id
        
        response = self.gmp.create_target(**kwargs)
        target_id = response.get("id")
        
        log.info("target_created", id=target_id)
        return target_id

    def delete_target(self, target_id: str):
        """Remove um target"""
        self.gmp.delete_target(target_id)

    # =========================================================================
    # Tasks
    # =========================================================================
    
    def create_task(
        self,
        name: str,
        target_id: str,
        config_id: Optional[str] = None,
        scanner_id: Optional[str] = None
    ) -> str:
        """
        Cria uma task de scan.
        
        Args:
            name: Nome da task
            target_id: ID do target a escanear
            config_id: ID da scan config (usa "Full and fast" se None)
            scanner_id: ID do scanner (usa "OpenVAS Default" se None)
            
        Returns:
            ID da task criada
        """
        if not config_id:
            config_id = self.get_scan_config_id("Full and fast")
        if not scanner_id:
            scanner_id = self.get_scanner_id("OpenVAS Default")
        
        log.info("creating_task", name=name, target_id=target_id)
        
        response = self.gmp.create_task(
            name=name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        
        task_id = response.get("id")
        log.info("task_created", id=task_id)
        return task_id

    def start_task(self, task_id: str) -> str:
        """
        Inicia uma task de scan.
        
        Returns:
            ID do report que será gerado
        """
        log.info("starting_task", task_id=task_id)
        response = self.gmp.start_task(task_id)
        
        report_id = response.find("report_id").text
        log.info("task_started", task_id=task_id, report_id=report_id)
        return report_id

    def stop_task(self, task_id: str):
        """Para uma task em execução"""
        self.gmp.stop_task(task_id)

    def get_task_status(self, task_id: str) -> tuple[ScanStatus, int]:
        """
        Obtém status e progresso de uma task.
        
        Returns:
            Tuple de (status, progresso em %)
        """
        response = self.gmp.get_task(task_id)
        
        status_text = response.find(".//status").text
        progress_elem = response.find(".//progress")
        progress = int(progress_elem.text) if progress_elem is not None and progress_elem.text else 0
        
        try:
            status = ScanStatus(status_text)
        except ValueError:
            status = ScanStatus.ERROR
        
        return status, progress

    def delete_task(self, task_id: str):
        """Remove uma task"""
        self.gmp.delete_task(task_id)

    # =========================================================================
    # Reports
    # =========================================================================
    
    def get_report_xml(self, report_id: str) -> str:
        """
        Obtém relatório em formato XML.
        
        Returns:
            String XML do relatório
        """
        log.info("getting_report", report_id=report_id)
        
        # Buscar ID do formato XML
        formats = self.gmp.get_report_formats()
        xml_format_id = None
        for fmt in formats.findall(".//report_format"):
            if fmt.find("name").text == "XML":
                xml_format_id = fmt.get("id")
                break
        
        if not xml_format_id:
            raise ValueError("XML report format not found")
        
        response = self.gmp.get_report(
            report_id=report_id,
            report_format_id=xml_format_id,
            ignore_pagination=True,
            details=True
        )
        
        report_elem = response.find(".//report")
        if report_elem is not None:
            return ET.tostring(report_elem, encoding="unicode")
        return ""

    def parse_report_summary(self, report_xml: str) -> VulnSummary:
        """
        Extrai resumo de vulnerabilidades do XML do relatório.
        
        Returns:
            VulnSummary com contagem de vulnerabilidades
        """
        summary = VulnSummary()
        
        try:
            root = ET.fromstring(report_xml)
            
            # Contar hosts
            hosts = root.findall(".//host")
            summary.hosts_scanned = len(hosts)
            
            # Contar vulnerabilidades por severidade
            results = root.findall(".//result")
            for result in results:
                severity_elem = result.find(".//severity")
                if severity_elem is not None and severity_elem.text:
                    severity = float(severity_elem.text)
                    if severity >= 7.0:
                        summary.vulns_high += 1
                    elif severity >= 4.0:
                        summary.vulns_medium += 1
                    elif severity > 0:
                        summary.vulns_low += 1
                    else:
                        summary.vulns_log += 1
                        
        except ET.ParseError as e:
            log.error("report_parse_error", error=str(e))
        
        return summary

    # =========================================================================
    # High-level scan operations
    # =========================================================================
    
    def run_full_scan(
        self,
        job_id: str,
        target_hosts: str,
        ports: Optional[list[int]] = None
    ) -> tuple[str, str, Optional[str]]:
        """
        Executa um scan completo.
        
        Cria os recursos necessários (target, port_list, task) e inicia o scan.
        
        Args:
            job_id: ID do job (usado para nomear recursos)
            target_hosts: Hosts a escanear
            ports: Lista de portas (None = todas)
            
        Returns:
            Tuple de (task_id, report_id, port_list_id ou None)
        """
        port_list_id = None
        
        # Criar port list se especificado
        if ports:
            port_list_id = self.create_port_list(
                name=f"job-{job_id}-ports",
                ports=ports
            )
        
        # Criar target
        target_id = self.create_target(
            name=f"job-{job_id}-target",
            hosts=target_hosts,
            port_list_id=port_list_id
        )
        
        # Criar task
        task_id = self.create_task(
            name=f"job-{job_id}",
            target_id=target_id
        )
        
        # Iniciar scan
        report_id = self.start_task(task_id)
        
        return task_id, report_id, port_list_id

    def cleanup_scan_resources(
        self,
        task_id: str,
        target_id: Optional[str] = None,
        port_list_id: Optional[str] = None
    ):
        """Remove recursos criados para um scan"""
        try:
            if task_id:
                self.delete_task(task_id)
        except Exception as e:
            log.warning("cleanup_task_failed", error=str(e))
        
        try:
            if target_id:
                self.delete_target(target_id)
        except Exception as e:
            log.warning("cleanup_target_failed", error=str(e))
        
        try:
            if port_list_id:
                self.delete_port_list(port_list_id)
        except Exception as e:
            log.warning("cleanup_port_list_failed", error=str(e))
