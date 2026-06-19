"""File identity checker: MIME type detection vs declared extension."""
import io
from dataclasses import dataclass
from pathlib import Path

import puremagic

# Map of lowercase extensions to their expected MIME type prefixes.
# We check that detected MIME *starts with* one of the allowed values.
EXTENSION_MIME_MAP: dict[str, list[str]] = {
    ".pdf":  ["application/pdf"],
    ".docx": [
        "application/vnd.openxmlformats-officedocument.wordprocessingml",
        "application/zip",  # OOXML is a zip container; puremagic may return this
    ],
    ".xlsx": [
        "application/vnd.openxmlformats-officedocument.spreadsheetml",
        "application/zip",
    ],
    ".txt":  ["text/plain", "text/"],
    ".rtf":  ["text/rtf", "application/rtf"],
}

# MIME prefixes that are immediately suspicious regardless of extension
SUSPICIOUS_MIME_PREFIXES: list[str] = [
    "application/x-dosexec",   # PE executable
    "application/x-executable",
    "application/x-sharedlib",
    "application/x-mach-binary",
    "application/x-sh",
    "application/x-shellscript",
]


@dataclass
class FileIdentityResult:
    filename: str
    extension: str
    declared_mime: str          # MIME implied by extension
    detected_mime: str          # MIME from magic bytes (best guess)
    extension_mismatch: bool
    is_suspicious_type: bool
    note: str = ""


def check_file_identity(data: bytes, filename: str) -> FileIdentityResult:
    """
    Detect the actual MIME type from file bytes and compare against
    the declared extension.
    """
    ext = Path(filename).suffix.lower()
    allowed_mimes = EXTENSION_MIME_MAP.get(ext, [])
    declared_mime = allowed_mimes[0] if allowed_mimes else "unknown"

    # puremagic returns a list of MagicMatch sorted by confidence
    try:
        matches = puremagic.magic_string(data)
        detected_mime = matches[0].mime_type if matches else "application/octet-stream"
    except Exception:
        detected_mime = "application/octet-stream"

    # Check for suspicious binaries first
    is_suspicious_type = any(
        detected_mime.startswith(p) for p in SUSPICIOUS_MIME_PREFIXES
    )

    # Extension mismatch: detected MIME doesn't match any allowed for this ext
    if allowed_mimes:
        extension_mismatch = not any(
            detected_mime.startswith(m) for m in allowed_mimes
        )
    else:
        # Unknown extension — flag it
        extension_mismatch = True

    note_parts = []
    if extension_mismatch:
        note_parts.append(
            f"Extension '{ext}' expects MIME like '{declared_mime}' "
            f"but detected '{detected_mime}'"
        )
    if is_suspicious_type:
        note_parts.append(f"Detected MIME '{detected_mime}' is a known executable/script type")

    return FileIdentityResult(
        filename=filename,
        extension=ext,
        declared_mime=declared_mime,
        detected_mime=detected_mime,
        extension_mismatch=extension_mismatch,
        is_suspicious_type=is_suspicious_type,
        note="; ".join(note_parts),
    )
