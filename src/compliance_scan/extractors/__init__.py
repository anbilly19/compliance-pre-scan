from .base import BaseExtractor, ExtractionResult
from .pdf import PdfExtractor
from .docx import DocxExtractor
from .xlsx import XlsxExtractor
from .txt import TxtExtractor
from .rtf import RtfExtractor

EXTRACTOR_MAP: dict[str, type[BaseExtractor]] = {
    ".pdf": PdfExtractor,
    ".docx": DocxExtractor,
    ".xlsx": XlsxExtractor,
    ".txt": TxtExtractor,
    ".rtf": RtfExtractor,
}


def get_extractor(extension: str) -> BaseExtractor | None:
    """Return an extractor instance for the given file extension, or None."""
    cls = EXTRACTOR_MAP.get(extension.lower())
    return cls() if cls else None


__all__ = [
    "BaseExtractor",
    "ExtractionResult",
    "PdfExtractor",
    "DocxExtractor",
    "XlsxExtractor",
    "TxtExtractor",
    "RtfExtractor",
    "get_extractor",
    "EXTRACTOR_MAP",
]
