"""
GVM Client - Interface com Greenbone Vulnerability Manager via GMP

Este módulo encapsula toda a comunicação com o GVM usando o protocolo GMP.
Compatível com python-gvm >= 24.0
"""

import os
from typing import Optional
from xml.etree import ElementTree as ET
from dataclasses import dataclass
from enum import Enum
from contextlib import contextmanager

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
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
    
    Uso:
        with GVMClient() as gvm:
            configs = gvm.get_scan_configs()
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
        
        self._gmp = None
        self._connection = None

    def __enter__(self):
        """Conecta ao GVM usando context manager"""
        log.info("gvm_connecting", host=self.host, port=self.port)
        
        self._connection = TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=self.timeout
        )
        
        # Usar GMP como context manager (API nova)
        self._gmp_ctx = Gmp(connection=self._connection)
        self._gmp = self._gmp_ctx.__enter__()
        
        # Autenticar
        self._gmp.authenticate(self.username, self.password)
        
        log.info("gvm_connected", host=self.host)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Desconecta do GVM"""
        if self._gmp_ctx:
            try:
                self._gmp_ctx.__exit__(exc_type, exc_val, exc_tb)
            except Exception:
                pass
        self._gmp = None
        self._connection = None

    @property
    def gmp(self):
        """Retorna instância GMP ativa"""
        if not self._gmp:
            raise RuntimeError("GVM not connected. Use 'with GVMClient() as gvm:'")
        return self._gmp

    # =========================================================================
    # Scan Configs
    # =========================================================================
    
    def get_scan_configs(self) -> list[ScanConfig]:
        """Lista configurações de scan disponíveis"""
        response = self.gmp.get_scan_configs()
        configs = []
        for config in response.findall(".//config"):
            name_elem = config.find("name")
            if name_elem is not None and name_elem.text:
                configs.append(ScanConfig(
                    id=config.get("id"),
                    name=name_elem.text
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
            name_elem = scanner.find("name")
            if name_elem is not None and name_elem.text:
                scanners.append(Scanner(
                    id=scanner.get("id"),
                    name=name_elem.text
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
            name_elem = pl.find("name")
            if name_elem is not None and name_elem.text:
                port_lists.append(PortList(
                    id=pl.get("id"),
                    name=name_elem.text
                ))
        return port_lists

    def create_port_list(self, name: str, ports: list[int]) -> str:
        """Cria uma port list customizada"""
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
    
    def create_target(self, name: str, hosts: str, port_list_id: Optional[str] = None) -> str:
        """Cria um target (alvo) para scan"""
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
    
    def create_task(self, name: str, target_id: str, config_id: Optional[str] = None, scanner_id: Optional[str] = None) -> str:
        """Cria uma task de scan"""
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
        """Inicia uma task de scan, retorna report_id"""
        log.info("starting_task", task_id=task_id)
        response = self.gmp.start_task(task_id)
        report_id = response.find("report_id").text
        log.info("task_started", task_id=task_id, report_id=report_id)
        return report_id

    def stop_task(self, task_id: str):
        """Para uma task em execução"""
        self.gmp.stop_task(task_id)

    def get_task_status(self, task_id: str) -> tuple[ScanStatus, int]:
        """Obtém status e progresso de uma task"""
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
        """Obtém relatório em formato XML"""
        log.info("getting_report", report_id=report_id)
        
        formats = self.gmp.get_report_formats()
        xml_format_id = None
        for fmt in formats.findall(".//report_format"):
            name_elem = fmt.find("name")
            if name_elem is not None and name_elem.text == "XML":
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
        """Extrai resumo de vulnerabilidades do XML"""
        summary = VulnSummary()
        
        try:
            root = ET.fromstring(report_xml)
            hosts = root.findall(".//host")
            summary.hosts_scanned = len(hosts)
            
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
