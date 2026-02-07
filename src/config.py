"""
Configuration loader — reads config.yaml and environment variables.

Environment variables override config.yaml values.
"""

import os
import logging
from dataclasses import dataclass, field, fields as dataclass_fields
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


@dataclass
class GVMConfig:
    host: str = "127.0.0.1"
    port: int = 9390
    username: str = "admin"
    password: str = "admin"
    timeout: int = 300
    retry_attempts: int = 3
    retry_delay: int = 5


@dataclass
class ProbeConfig:
    name: str = "default"
    gvm: GVMConfig = field(default_factory=GVMConfig)


@dataclass
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass
class ScanConfig:
    poll_interval: int = 30
    max_duration: int = 86400
    cleanup_after_report: bool = True
    default_port_list: str = "All IANA assigned TCP"
    max_consecutive_same_probe: int = 3


@dataclass
class SourceConfig:
    url: str = ""
    auth_token: str = ""
    sync_interval: int = 300
    callback_url: str = ""
    timeout: int = 30
    scheduler_interval: int = 60


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "console"


@dataclass
class AppConfig:
    probes: list = field(default_factory=lambda: [ProbeConfig()])
    api: APIConfig = field(default_factory=APIConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    source: SourceConfig = field(default_factory=SourceConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)


def load_config(config_path: str = None) -> AppConfig:
    """
    Load configuration from YAML file, then override with environment variables.
    
    Priority: env vars > config.yaml > defaults
    """
    config = AppConfig()

    # Load from YAML if available
    if config_path is None:
        config_path = os.getenv("CONFIG_PATH", "config.yaml")

    path = Path(config_path)
    if path.exists():
        with open(path) as f:
            data = yaml.safe_load(f) or {}

        api_data = data.get("api", {})
        scan_data = data.get("scan", {})
        source_data = data.get("source", {})
        logging_data = data.get("logging", {})

        config.probes = _load_probes(data)
        config.api = _build_dataclass(APIConfig, api_data, "api")
        config.scan = _build_dataclass(ScanConfig, scan_data, "scan")
        config.source = _build_dataclass(SourceConfig, source_data, "source")
        config.logging = _build_dataclass(LoggingConfig, logging_data, "logging")

    # Override with environment variables
    _apply_env_overrides(config)

    return config


def _build_dataclass(cls, data: dict, section_name: str):
    """Build a dataclass instance, warning on unknown keys."""
    valid_keys = {f.name for f in dataclass_fields(cls)}
    filtered = {}
    for k, v in data.items():
        if k not in valid_keys:
            log.warning(
                "Unknown config key '%s' in section '%s'. "
                "Valid keys: %s", k, section_name, sorted(valid_keys)
            )
        elif v is not None:
            filtered[k] = v
    return cls(**filtered)


def _load_probes(data: dict) -> list:
    """Load probe configs. Supports both 'probes' list and legacy single 'gvm' section."""
    probes_data = data.get("probes", [])
    gvm_data = data.get("gvm", {})

    if probes_data:
        result = []
        for i, p in enumerate(probes_data):
            name = p.get("name", f"probe-{i+1}")
            gvm_section = {k: v for k, v in p.items() if k != "name"}
            gvm_cfg = _build_dataclass(GVMConfig, gvm_section, f"probes[{name}]")
            result.append(ProbeConfig(name=name, gvm=gvm_cfg))
        return result

    if gvm_data:
        gvm_cfg = _build_dataclass(GVMConfig, gvm_data, "gvm")
        return [ProbeConfig(name="default", gvm=gvm_cfg)]

    return [ProbeConfig()]


def _apply_env_overrides(config: AppConfig):
    """Override config values with environment variables when set."""
    # GVM env vars apply to the first probe (backward compat)
    first_gvm = config.probes[0].gvm if config.probes else None

    env_map = {
        "API_HOST": (config.api, "host", str),
        "API_PORT": (config.api, "port", int),
        "SCAN_POLL_INTERVAL": (config.scan, "poll_interval", int),
        "SCAN_MAX_DURATION": (config.scan, "max_duration", int),
        "SCAN_CLEANUP": (config.scan, "cleanup_after_report", lambda v: v.lower() in ("true", "1", "yes")),
        "SCAN_DEFAULT_PORT_LIST": (config.scan, "default_port_list", str),
        "SOURCE_URL": (config.source, "url", str),
        "SOURCE_AUTH_TOKEN": (config.source, "auth_token", str),
        "SOURCE_SYNC_INTERVAL": (config.source, "sync_interval", int),
        "SOURCE_CALLBACK_URL": (config.source, "callback_url", str),
        "SOURCE_TIMEOUT": (config.source, "timeout", int),
        "SOURCE_SCHEDULER_INTERVAL": (config.source, "scheduler_interval", int),
        "LOG_LEVEL": (config.logging, "level", str),
        "LOG_FORMAT": (config.logging, "format", str),
    }

    if first_gvm:
        env_map.update({
            "GVM_HOST": (first_gvm, "host", str),
            "GVM_PORT": (first_gvm, "port", int),
            "GVM_USERNAME": (first_gvm, "username", str),
            "GVM_PASSWORD": (first_gvm, "password", str),
            "GVM_TIMEOUT": (first_gvm, "timeout", int),
            "GVM_RETRY_ATTEMPTS": (first_gvm, "retry_attempts", int),
            "GVM_RETRY_DELAY": (first_gvm, "retry_delay", int),
        })

    for env_key, (obj, attr, cast) in env_map.items():
        value = os.getenv(env_key)
        if value is not None and value != "":
            setattr(obj, attr, cast(value))
