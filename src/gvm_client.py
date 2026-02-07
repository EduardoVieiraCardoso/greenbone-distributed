"""
GVM Client — Interface with Greenbone Vulnerability Manager via GMP protocol.

All interactions use the standard GMP protocol. No modifications to GVM.
Compatible with python-gvm >= 26.0.

Usage:
    client = GVMClient(config)
    with client.connect() as gvm:
        configs = gvm.get_scan_configs()
"""

import time
from typing import Optional
from xml.etree import ElementTree as ET
from dataclasses import dataclass
from contextlib import contextmanager

from gvm.connections import TLSConnection
from gvm.protocols.gmp import Gmp
import structlog

try:
    from gvm.protocols.gmp import AliveTest
except ImportError:
    try:
        from gvm.protocols.gmp.requests import AliveTest
    except ImportError:
        AliveTest = None

# Mapping from config string to AliveTest enum (if available)
ALIVE_TEST_MAP = {
    "Scan Config Default": "SCAN_CONFIG_DEFAULT",
    "ICMP Ping": "ICMP_PING",
    "TCP-ACK Service Ping": "TCP_ACK_SERVICE_PING",
    "TCP-SYN Service Ping": "TCP_SYN_SERVICE_PING",
    "ARP Ping": "ARP_PING",
    "ICMP & TCP-ACK Service Ping": "ICMP_AND_TCP_ACK_SERVICE_PING",
    "ICMP & ARP Ping": "ICMP_AND_ARP_PING",
    "TCP-ACK Service & ARP Ping": "TCP_ACK_SERVICE_AND_ARP_PING",
    "ICMP, TCP-ACK Service & ARP Ping": "ICMP_TCP_ACK_SERVICE_AND_ARP_PING",
    "Consider Alive": "CONSIDER_ALIVE",
}

from .config import GVMConfig

log = structlog.get_logger()


# =============================================================================
# Data Classes
# =============================================================================

@dataclass
class ScanConfigInfo:
    """Scan configuration available in GVM."""
    id: str
    name: str


@dataclass
class ScannerInfo:
    """Scanner available in GVM."""
    id: str
    name: str


@dataclass
class PortListInfo:
    """Port list in GVM."""
    id: str
    name: str


@dataclass
class VulnSummary:
    """Vulnerability summary extracted from a GVM report."""
    hosts_scanned: int = 0
    vulns_high: int = 0
    vulns_medium: int = 0
    vulns_low: int = 0
    vulns_log: int = 0


# =============================================================================
# GVM Client
# =============================================================================

class GVMClient:
    """
    Client for communicating with GVM via GMP (Greenbone Management Protocol).

    GMP is an XML-over-TLS protocol for full GVM control.
    The immauss/openvas image exposes gvmd on port 9390.
    """

    def __init__(self, config: GVMConfig):
        self.host = config.host
        self.port = config.port
        self.username = config.username
        self.password = config.password
        self.timeout = config.timeout
        self.retry_attempts = config.retry_attempts
        self.retry_delay = config.retry_delay

    @contextmanager
    def connect(self):
        """
        Connect to GVM with automatic retry on connection only.

        Yields a connected GVMSession.
        Retry logic applies only to the initial connection, not to operations
        performed within the session.

        Usage:
            with client.connect() as gvm:
                gvm.get_scan_configs()
        """
        session = self._connect_with_retry()
        try:
            yield session
        finally:
            session.close()

    def _connect_with_retry(self) -> "GVMSession":
        """Attempt to connect to GVM, retrying on failure."""
        last_error = None

        for attempt in range(1, self.retry_attempts + 1):
            try:
                return self._create_session()
            except Exception as e:
                last_error = e
                if attempt < self.retry_attempts:
                    log.warning("gvm_connection_failed_retrying",
                                attempt=attempt,
                                max_attempts=self.retry_attempts,
                                error=str(e),
                                retry_in=self.retry_delay)
                    time.sleep(self.retry_delay)
                else:
                    log.error("gvm_connection_failed_all_attempts",
                              attempts=self.retry_attempts,
                              error=str(e))

        raise ConnectionError(
            f"Failed to connect to GVM at {self.host}:{self.port} "
            f"after {self.retry_attempts} attempts: {last_error}"
        )

    def _create_session(self) -> "GVMSession":
        """Create and authenticate a GVM session."""
        log.info("gvm_connecting", host=self.host, port=self.port)

        connection = TLSConnection(
            hostname=self.host,
            port=self.port,
            timeout=self.timeout
        )

        gmp = Gmp(connection=connection)
        gmp.connect()

        try:
            proto = gmp.determine_supported_gmp()
            proto.authenticate(self.username, self.password)
            log.info("gvm_connected", host=self.host)
            return GVMSession(gmp, proto)
        except Exception:
            gmp.disconnect()
            raise


class GVMSession:
    """
    An authenticated GVM session.

    Wraps the Gmp connection and versioned protocol object.
    """

    def __init__(self, gmp: Gmp, proto):
        self._gmp = gmp
        self._proto = proto

    def close(self):
        """Close the GMP connection."""
        if self._gmp:
            self._gmp.disconnect()
            self._gmp = None
            self._proto = None

    @property
    def gmp(self):
        if not self._proto:
            raise RuntimeError("GVM session is closed")
        return self._proto

    @staticmethod
    def _parse(response) -> ET.Element:
        """Parse GMP response to an XML element (python-gvm 26.x returns strings)."""
        if isinstance(response, str):
            return ET.fromstring(response)
        return response

    @staticmethod
    def _check_response(response: ET.Element, operation: str) -> ET.Element:
        """Validate GMP response status. Raises RuntimeError with GVM error message on failure."""
        status = response.get("status", "")
        if not status.startswith(("2", "1")):
            status_text = response.get("status_text", "Unknown error")
            raise RuntimeError(f"GVM {operation} failed (status {status}): {status_text}")
        return response

    # =========================================================================
    # Scan Configs
    # =========================================================================

    def get_scan_configs(self) -> list[ScanConfigInfo]:
        """List available scan configurations."""
        response = self._parse(self.gmp.get_scan_configs())
        configs = []
        for config in response.findall(".//config"):
            name_elem = config.find("name")
            if name_elem is not None and name_elem.text:
                configs.append(ScanConfigInfo(
                    id=config.get("id"),
                    name=name_elem.text
                ))
        return configs

    def get_scan_config_id(self, name: str = "Full and fast") -> str:
        """Get scan config ID by name."""
        configs = self.get_scan_configs()
        for config in configs:
            if config.name == name:
                return config.id
        raise ValueError(
            f"Scan config '{name}' not found. "
            f"Available: {[c.name for c in configs]}"
        )

    # =========================================================================
    # Scanners
    # =========================================================================

    def get_scanners(self) -> list[ScannerInfo]:
        """List available scanners."""
        response = self._parse(self.gmp.get_scanners())
        scanners = []
        for scanner in response.findall(".//scanner"):
            name_elem = scanner.find("name")
            if name_elem is not None and name_elem.text:
                scanners.append(ScannerInfo(
                    id=scanner.get("id"),
                    name=name_elem.text
                ))
        return scanners

    def get_scanner_id(self, name: str = "OpenVAS Default") -> str:
        """Get scanner ID by name."""
        scanners = self.get_scanners()
        for scanner in scanners:
            if scanner.name == name:
                return scanner.id
        raise ValueError(
            f"Scanner '{name}' not found. "
            f"Available: {[s.name for s in scanners]}"
        )

    # =========================================================================
    # Port Lists
    # =========================================================================

    def get_port_lists(self) -> list[PortListInfo]:
        """List available port lists."""
        response = self._parse(self.gmp.get_port_lists())
        port_lists = []
        for pl in response.findall(".//port_list"):
            name_elem = pl.find("name")
            if name_elem is not None and name_elem.text:
                port_lists.append(PortListInfo(
                    id=pl.get("id"),
                    name=name_elem.text
                ))
        return port_lists

    def get_port_list_id(self, name: str) -> str:
        """Get port list ID by name."""
        port_lists = self.get_port_lists()
        for pl in port_lists:
            if pl.name == name:
                return pl.id
        raise ValueError(
            f"Port list '{name}' not found. "
            f"Available: {[p.name for p in port_lists]}"
        )

    def create_port_list(self, name: str, ports: list[int]) -> str:
        """Create a custom port list. Returns port_list_id."""
        port_range = ",".join(f"T:{p}" for p in ports)
        log.info("creating_port_list", name=name, ports=ports)
        response = self._parse(self.gmp.create_port_list(name=name, port_range=port_range))
        self._check_response(response, "create_port_list")
        port_list_id = response.get("id")
        if not port_list_id:
            raise RuntimeError(f"GVM did not return an ID when creating port list '{name}'")
        log.info("port_list_created", id=port_list_id)
        return port_list_id

    def delete_port_list(self, port_list_id: str):
        """Delete a port list."""
        self.gmp.delete_port_list(port_list_id)

    # =========================================================================
    # Targets
    # =========================================================================

    def _resolve_alive_test(self, alive_test_name: str):
        """Resolve alive test config string to python-gvm AliveTest enum."""
        if not alive_test_name or AliveTest is None:
            return None
        enum_name = ALIVE_TEST_MAP.get(alive_test_name)
        if not enum_name:
            log.warning("unknown_alive_test", name=alive_test_name,
                        available=list(ALIVE_TEST_MAP.keys()))
            return None
        try:
            return AliveTest[enum_name]
        except (KeyError, TypeError):
            log.warning("alive_test_enum_not_found", name=enum_name)
            return None

    def create_target(self, name: str, hosts: str,
                      port_list_id: Optional[str] = None,
                      default_port_list_name: Optional[str] = None,
                      alive_test_name: Optional[str] = None) -> str:
        """Create a scan target. Returns target_id."""
        log.info("creating_target", name=name, hosts=hosts, alive_test=alive_test_name)

        if not port_list_id:
            lookup_name = default_port_list_name or "All IANA assigned TCP"
            port_list_id = self.get_port_list_id(lookup_name)

        kwargs = {"name": name, "hosts": [hosts], "port_list_id": port_list_id}

        alive_test = self._resolve_alive_test(alive_test_name)
        if alive_test:
            kwargs["alive_test"] = alive_test

        response = self._parse(self.gmp.create_target(**kwargs))
        self._check_response(response, "create_target")
        target_id = response.get("id")
        if not target_id:
            raise RuntimeError(f"GVM did not return an ID when creating target '{name}'")
        log.info("target_created", id=target_id)
        return target_id

    def delete_target(self, target_id: str):
        """Delete a target."""
        self.gmp.delete_target(target_id)

    # =========================================================================
    # Tasks
    # =========================================================================

    def create_task(self, name: str, target_id: str,
                    config_id: Optional[str] = None,
                    scanner_id: Optional[str] = None,
                    config_name: str = "Full and fast",
                    scanner_name: str = "OpenVAS Default") -> str:
        """Create a scan task. Returns task_id."""
        if not config_id:
            config_id = self.get_scan_config_id(config_name)
        if not scanner_id:
            scanner_id = self.get_scanner_id(scanner_name)

        log.info("creating_task", name=name, target_id=target_id)

        response = self._parse(self.gmp.create_task(
            name=name,
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        ))
        self._check_response(response, "create_task")

        task_id = response.get("id")
        if not task_id:
            raise RuntimeError(f"GVM did not return an ID when creating task '{name}'")
        log.info("task_created", id=task_id)
        return task_id

    def start_task(self, task_id: str) -> str:
        """Start a scan task. Returns report_id."""
        log.info("starting_task", task_id=task_id)
        response = self._parse(self.gmp.start_task(task_id))
        self._check_response(response, "start_task")
        report_id_elem = response.find("report_id")
        if report_id_elem is None or not report_id_elem.text:
            raise RuntimeError(f"GVM did not return a report_id when starting task {task_id}")
        report_id = report_id_elem.text
        log.info("task_started", task_id=task_id, report_id=report_id)
        return report_id

    def stop_task(self, task_id: str):
        """Stop a running task."""
        self.gmp.stop_task(task_id)

    def delete_task(self, task_id: str):
        """Delete a task."""
        self.gmp.delete_task(task_id)

    def get_task_status(self, task_id: str) -> tuple[str, int]:
        """
        Get real task status and progress from GVM.

        Returns:
            (status_text, progress) where status_text is the raw GVM status
            string and progress is 0-100.
        """
        response = self._parse(self.gmp.get_task(task_id))

        status_elem = response.find(".//status")
        if status_elem is None or not status_elem.text:
            raise RuntimeError(f"GVM returned no status for task {task_id}")
        status_text = status_elem.text

        progress_elem = response.find(".//progress")
        progress = 0
        if progress_elem is not None and progress_elem.text:
            progress = max(0, int(progress_elem.text))

        return status_text, progress

    # =========================================================================
    # Reports
    # =========================================================================

    def get_report_xml(self, report_id: str) -> str:
        """Get the full XML report from GVM."""
        log.info("getting_report", report_id=report_id)

        # Find XML report format ID
        formats = self._parse(self.gmp.get_report_formats())
        xml_format_id = None
        for fmt in formats.findall(".//report_format"):
            name_elem = fmt.find("name")
            if name_elem is not None and name_elem.text == "XML":
                xml_format_id = fmt.get("id")
                break

        if not xml_format_id:
            raise ValueError("XML report format not found in GVM")

        response = self._parse(self.gmp.get_report(
            report_id=report_id,
            report_format_id=xml_format_id,
            ignore_pagination=True,
            details=True
        ))

        report_elem = response.find(".//report")
        if report_elem is None:
            raise RuntimeError(f"GVM returned no report element for report_id {report_id}")
        return ET.tostring(report_elem, encoding="unicode")

    def parse_report_summary(self, report_xml: str) -> VulnSummary:
        """Extract vulnerability summary from XML report."""
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
