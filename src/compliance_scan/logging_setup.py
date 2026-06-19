"""Centralised logging configuration.

Importing this module IMMEDIATELY creates logs/compliance_scan.log
relative to the repo root (two levels up from this file).

Call configure_logging() to customise levels; it is also called
automatically on first import so the log file always exists.
"""
from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

_CONFIGURED = False

_FMT    = "%(asctime)s %(levelname)-8s %(name)s - %(message)s"
_DATEFMT = "%Y-%m-%d %H:%M:%S"

# Repo root = three levels up from src/compliance_scan/logging_setup.py
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_DEFAULT_LOG_DIR = _REPO_ROOT / "logs"


def configure_logging(
    log_dir: Path | str | None = None,
    log_filename: str = "compliance_scan.log",
    file_level: int = logging.DEBUG,
    console_level: int = logging.DEBUG,
    max_bytes: int = 5 * 1024 * 1024,
    backup_count: int = 5,
) -> Path:
    """
    Set up rotating file + console handlers.
    Returns the absolute path of the log file.
    Safe to call multiple times (only configures once).
    """
    global _CONFIGURED
    if _CONFIGURED:
        return _DEFAULT_LOG_DIR / log_filename
    _CONFIGURED = True

    log_path = Path(log_dir).resolve() if log_dir else _DEFAULT_LOG_DIR
    log_path.mkdir(parents=True, exist_ok=True)
    log_file = log_path / log_filename

    formatter = logging.Formatter(_FMT, datefmt=_DATEFMT)

    fh = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
    )
    fh.setLevel(file_level)
    fh.setFormatter(formatter)

    ch = logging.StreamHandler()
    ch.setLevel(console_level)
    ch.setFormatter(formatter)

    root = logging.getLogger()
    root.handlers.clear()  # remove pytest/uvicorn defaults
    root.setLevel(logging.DEBUG)
    root.addHandler(fh)
    root.addHandler(ch)

    pkg = logging.getLogger("compliance_scan")
    pkg.setLevel(logging.DEBUG)
    pkg.propagate = True

    pkg.info("Logging initialised -> %s", log_file)
    return log_file


# Auto-configure on import so ANY entry point gets a log file
configure_logging()
