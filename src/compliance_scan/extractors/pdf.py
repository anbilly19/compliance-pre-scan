import io
import fitz  # pymupdf
from .base import BaseExtractor, ExtractionResult


class PdfExtractor(BaseExtractor):
    """Extract text from PDF files using PyMuPDF."""

    def extract(self, data: bytes, filename: str) -> ExtractionResult:
        text_parts: list[str] = []
        page_count = 0

        with fitz.open(stream=io.BytesIO(data), filetype="pdf") as doc:
            page_count = doc.page_count
            for page in doc:
                text_parts.append(page.get_text())

        return ExtractionResult(
            text="\n".join(text_parts),
            page_count=page_count,
            raw_byte_size=len(data),
        )
