"""compliance_scan: local pre-upload content security scanner.

Importing logging_setup here guarantees configure_logging() fires
regardless of entry point (uvicorn, streamlit, pytest, CLI).
"""
from . import logging_setup as _logging_setup  # noqa: F401  side-effect import

__all__: list[str] = []
