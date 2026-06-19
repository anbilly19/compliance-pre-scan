"""RTF extractor – strips RTF control codes with a lightweight regex approach."""
import re
from pathlib import Path

from .base import BaseExtractor, ExtractionResult

# Strip RTF control words, groups, and binary blobs
_CONTROL_WORD = re.compile(r"\\[a-z]+[-\d]*[ ]?")
_CONTROL_SYMBOL = re.compile(r"\\[^a-z]")  
_BINARY_BLOB = re.compile(r"\\bin\d+", re.IGNORECASE)
_BRACES = re.compile(r"[{}]")


def _rtf_to_text(raw: str) -> str:
    # Remove binary blob markers
    text = _BINARY_BLOB.sub("", raw)
    # Replace RTF paragraph markers with newlines
    text = text.replace(r"\par", "\n").replace(r"\line", "\n")
    # Strip control words and symbols
    text = _CONTROL_WORD.sub("", text)
    text = _CONTROL_SYMBOL.sub("", text)
    text = _BRACES.sub("", text)
    # Collapse whitespace
    lines = [l.strip() for l in text.splitlines() if l.strip()]
    return "\n".join(lines)


class RTFExtractor(BaseExtractor):
    def extract(self, path: Path) -> ExtractionResult:
        warnings: list[str] = []
        text = ""

        try:
            raw = path.read_text(encoding="latin-1", errors="replace")
            text = _rtf_to_text(raw)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"RTF read error: {exc}")

        return ExtractionResult(
            text=text,
            page_count=1,
            extraction_warnings=warnings,
        )
