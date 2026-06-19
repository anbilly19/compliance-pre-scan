"""Plain-text extractor; handles common encodings gracefully."""
from pathlib import Path

from .base import BaseExtractor, ExtractionResult

_ENCODINGS = ("utf-8", "utf-8-sig", "latin-1", "cp1252")


class TXTExtractor(BaseExtractor):
    def extract(self, path: Path) -> ExtractionResult:
        warnings: list[str] = []
        text = ""

        for enc in _ENCODINGS:
            try:
                text = path.read_text(encoding=enc)
                break
            except (UnicodeDecodeError, ValueError):
                continue
        else:
            warnings.append("Could not decode text with any supported encoding.")

        return ExtractionResult(
            text=text,
            page_count=1,
            extraction_warnings=warnings,
        )
