from striprtf.striprtf import rtf_to_text
from .base import BaseExtractor, ExtractionResult


class RtfExtractor(BaseExtractor):
    """Extract text from RTF files."""

    def extract(self, data: bytes, filename: str) -> ExtractionResult:
        try:
            raw = data.decode("utf-8", errors="replace")
        except Exception:
            raw = data.decode("latin-1", errors="replace")

        text = rtf_to_text(raw)

        return ExtractionResult(
            text=text,
            page_count=0,
            raw_byte_size=len(data),
        )
