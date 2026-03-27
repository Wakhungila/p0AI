"""
pin0ccsAI — Logging System
Structured logging with structlog. JSON in production, pretty console in dev.
"""
from __future__ import annotations

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Any

import structlog


_initialized = False


def setup_logging(
    level: str = "INFO",
    fmt: str = "console",
    log_to_file: bool = True,
    log_dir: str = "./logs",
    max_bytes: int = 10_485_760,
    backup_count: int = 5,
) -> None:
    global _initialized
    if _initialized:
        return

    numeric_level = getattr(logging, level.upper(), logging.INFO)

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stderr)]

    if log_to_file:
        log_path = Path(log_dir) / "pin0ccs.log"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        rotating = logging.handlers.RotatingFileHandler(
            log_path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        handlers.append(rotating)

    logging.basicConfig(
        format="%(message)s",
        level=numeric_level,
        handlers=handlers,
    )

    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]

    if fmt == "json":
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=True)

    structlog.configure(
        processors=shared_processors + [
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processor=renderer,
        foreign_pre_chain=shared_processors,
    )

    for handler in handlers:
        handler.setFormatter(formatter)

    _initialized = True


def get_logger(name: str, **ctx: Any) -> structlog.stdlib.BoundLogger:
    """Return a bound logger for the given module name with optional context."""
    logger = structlog.get_logger(name)
    if ctx:
        logger = logger.bind(**ctx)
    return logger


def bind_scan_context(target: str, scan_id: str) -> None:
    """Bind scan-level context to all subsequent log calls in this coroutine."""
    structlog.contextvars.bind_contextvars(target=target, scan_id=scan_id)


def clear_scan_context() -> None:
    structlog.contextvars.clear_contextvars()
