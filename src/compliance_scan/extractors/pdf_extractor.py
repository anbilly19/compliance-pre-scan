"""PDF text extractor using pypdf."""
from pathlib import Path

from .base import BaseExtractor, ExtractionResult


class PDFExtractor(BaseExtractor):
    def extract(self, path: Path) -> ExtractionResult:
        try:
            import pypdf  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("pypdf is required: pip install pypdf") from exc

        pages_text: list[str] = []
        warnings: list[str] = []

        try:
            reader = pypdf.PdfReader(str(path))
            for page in reader.pages:
                pages_text.append(page.extract_text() or "")
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"PDF read error: {exc}")

        return ExtractionResult(
            text="\n".join(pages_text),
            page_count=len(pages_text),
            extraction_warnings=warnings,
        )
