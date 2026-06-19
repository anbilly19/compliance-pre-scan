"""Route a file to the correct extractor by detected MIME type."""
from pathlib import Path

from .base import ExtractionResult
from .pdf_extractor import PDFExtractor
from .docx_extractor import DOCXExtractor
from .txt_extractor import TXTExtractor
from .xlsx_extractor import XLSXExtractor
from .rtf_extractor import RTFExtractor

_EXTRACTORS: dict[str, object] = {
    "application/pdf": PDFExtractor(),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": DOCXExtractor(),
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": XLSXExtractor(),
    "text/plain": TXTExtractor(),
    "text/rtf": RTFExtractor(),
    "application/rtf": RTFExtractor(),
}

# Fallback by extension when MIME detection gives a generic type
_EXT_MAP: dict[str, object] = {
    ".pdf": PDFExtractor(),
    ".docx": DOCXExtractor(),
    ".doc": DOCXExtractor(),
    ".txt": TXTExtractor(),
    ".xlsx": XLSXExtractor(),
    ".xlsm": XLSXExtractor(),
    ".rtf": RTFExtractor(),
}


def extract_text(path: Path, mime_type: str | None = None) -> ExtractionResult:
    """
    Dispatch to the correct extractor.
    Prefers MIME type; falls back to file extension.
    """
    if mime_type and mime_type in _EXTRACTORS:
        return _EXTRACTORS[mime_type].extract(path)

    ext = path.suffix.lower()
    if ext in _EXT_MAP:
        return _EXT_MAP[ext].extract(path)

    return ExtractionResult(
        text="",
        extraction_warnings=[f"No extractor available for type={mime_type!r} / ext={ext!r}"],
    )
