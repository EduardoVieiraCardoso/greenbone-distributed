"""
Greenbone Adapter — Entry point.

Starts the FastAPI server with configuration from config.yaml / env vars.
"""

import logging
import sys

import structlog
import uvicorn

from .config import load_config
from .api import create_app


def setup_logging(level: str, fmt: str):
    """Configure structlog."""
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
    ]

    if fmt == "console":
        processors.append(structlog.dev.ConsoleRenderer())
    else:
        processors.append(structlog.processors.JSONRenderer())

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
    )

    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(message)s",
        stream=sys.stdout,
    )


def main():
    config = load_config()

    setup_logging(config.logging.level, config.logging.format)

    log = structlog.get_logger()
    log.info("config_loaded",
             gvm_host=config.gvm.host,
             gvm_port=config.gvm.port,
             api_port=config.api.port,
             poll_interval=config.scan.poll_interval)

    app = create_app(config)

    uvicorn.run(
        app,
        host=config.api.host,
        port=config.api.port,
    )


if __name__ == "__main__":
    main()
