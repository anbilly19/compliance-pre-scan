from .base import BaseExtractor, ExtractionResult


class TxtExtractor(BaseExtractor):
    """Extract text from plain-text files."""

    def extract(self, data: bytes, filename: str) -> ExtractionResult:
        # try utf-8 first, fall back to latin-1 to avoid decode errors
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            text = data.decode("latin-1", errors="replace")

        return ExtractionResult(
            text=text,
            page_count=0,
            raw_byte_size=len(data),
        )
