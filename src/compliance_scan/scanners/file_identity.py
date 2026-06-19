"""MIME-type detection using puremagic (pure Python, no C deps)."""
from dataclasses import dataclass
from pathlib import Path

import puremagic

# Allowlist of MIME types the platform accepts
_ALLOWED_MIMES = {
    "application/pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
    "text/rtf",
    "application/rtf",
    "application/msword",         # legacy .doc
    "application/vnd.ms-excel",   # legacy .xls
}

_EXT_MIME_MAP = {
    ".pdf":  "application/pdf",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".doc":  "application/msword",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".xlsm": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".txt":  "text/plain",
    ".rtf":  "text/rtf",
}


@dataclass
class FileIdentity:
    mime_detected: str
    mime_from_extension: str
    extension_mismatch: bool
    is_allowed_type: bool


def identify_file(path: Path) -> FileIdentity:
    """Detect true MIME type and compare against declared extension."""
    ext = path.suffix.lower()
    mime_from_ext = _EXT_MIME_MAP.get(ext, "application/octet-stream")

    mime_detected = "application/octet-stream"
    try:
        matches = puremagic.magic_file(str(path))
        if matches:
            # puremagic returns a list of PureMagicWithConfidence; take highest confidence
            matches.sort(key=lambda m: m.confidence, reverse=True)
            mime_detected = matches[0].mime_type or "application/octet-stream"
    except Exception:  # noqa: BLE001
        pass

    # Mismatch: detected type and extension-expected type differ in major family
    def _major(mime: str) -> str:
        return mime.split("/")[0]

    mismatch = (
        mime_detected != "application/octet-stream"
        and _major(mime_detected) != _major(mime_from_ext)
    )

    return FileIdentity(
        mime_detected=mime_detected,
        mime_from_extension=mime_from_ext,
        extension_mismatch=mismatch,
        is_allowed_type=mime_detected in _ALLOWED_MIMES or mime_from_ext in _ALLOWED_MIMES,
    )
