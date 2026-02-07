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
class APIConfig:
    host: str = "0.0.0.0"
    port: int = 8080


@dataclass
class ScanConfig:
    poll_interval: int = 30
    max_duration: int = 86400
    cleanup_after_report: bool = True
    default_port_list: str = "All IANA assigned TCP"


@dataclass
class LoggingConfig:
    level: str = "INFO"
    format: str = "console"


@dataclass
class AppConfig:
    gvm: GVMConfig = field(default_factory=GVMConfig)
    api: APIConfig = field(default_factory=APIConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
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

        gvm_data = data.get("gvm", {})
        api_data = data.get("api", {})
        scan_data = data.get("scan", {})
        logging_data = data.get("logging", {})

        config.gvm = _build_dataclass(GVMConfig, gvm_data, "gvm")
        config.api = _build_dataclass(APIConfig, api_data, "api")
        config.scan = _build_dataclass(ScanConfig, scan_data, "scan")
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


def _apply_env_overrides(config: AppConfig):
    """Override config values with environment variables when set."""
    env_map = {
        "GVM_HOST": (config.gvm, "host", str),
        "GVM_PORT": (config.gvm, "port", int),
        "GVM_USERNAME": (config.gvm, "username", str),
        "GVM_PASSWORD": (config.gvm, "password", str),
        "GVM_TIMEOUT": (config.gvm, "timeout", int),
        "GVM_RETRY_ATTEMPTS": (config.gvm, "retry_attempts", int),
        "GVM_RETRY_DELAY": (config.gvm, "retry_delay", int),
        "API_HOST": (config.api, "host", str),
        "API_PORT": (config.api, "port", int),
        "SCAN_POLL_INTERVAL": (config.scan, "poll_interval", int),
        "SCAN_MAX_DURATION": (config.scan, "max_duration", int),
        "SCAN_CLEANUP": (config.scan, "cleanup_after_report", lambda v: v.lower() in ("true", "1", "yes")),
        "SCAN_DEFAULT_PORT_LIST": (config.scan, "default_port_list", str),
        "LOG_LEVEL": (config.logging, "level", str),
        "LOG_FORMAT": (config.logging, "format", str),
    }

    for env_key, (obj, attr, cast) in env_map.items():
        value = os.getenv(env_key)
        if value is not None and value != "":
            setattr(obj, attr, cast(value))
