"""Centralised logging configuration for compliance-pre-scan.

Call configure_logging() once at process startup (main.py lifespan).
All compliance_scan.* loggers emit DEBUG+ to the rotating log file so
every scan, hit, and suppression decision is recorded.
Third-party libraries (spaCy, Presidio, uvicorn) stay at INFO to avoid spam.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_CONFIGURED = False

_FMT = "%(asctime)s %(levelname)-8s %(name)s - %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"


def configure_logging(
    log_dir: Path | str = "logs",
    log_filename: str = "compliance_scan.log",
    file_level: int = logging.DEBUG,
    console_level: int = logging.INFO,
    max_bytes: int = 5 * 1024 * 1024,  # 5 MB
    backup_count: int = 5,
) -> None:
    """Set up rotating file handler + console handler.

    Safe to call multiple times — only configures once per process.
    """
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    log_path = Path(log_dir)
    log_path.mkdir(parents=True, exist_ok=True)

    formatter = logging.Formatter(_FMT, datefmt=_DATEFMT)

    # --- Rotating file handler (DEBUG+) ---
    file_handler = logging.handlers.RotatingFileHandler(
        log_path / log_filename,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setLevel(file_level)
    file_handler.setFormatter(formatter)

    # --- Console handler (INFO+) ---
    console_handler = logging.StreamHandler()
    console_handler.setLevel(console_level)
    console_handler.setFormatter(formatter)

    # --- Root logger: INFO so 3rd-party libs don't flood the file ---
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    root.addHandler(file_handler)
    root.addHandler(console_handler)

    # --- Our own package: DEBUG so every decision is visible ---
    pkg_logger = logging.getLogger("compliance_scan")
    pkg_logger.setLevel(logging.DEBUG)

    pkg_logger.info(
        "Logging initialised — file=%s level=DEBUG console level=INFO",
        log_path / log_filename,
    )
