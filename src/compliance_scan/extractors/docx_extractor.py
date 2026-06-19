"""DOCX extractor using python-docx; detects macros and OLE objects."""
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from .base import BaseExtractor, ExtractionResult

# OOXML paths that indicate active content
_MACRO_PATHS = (
    "word/vbaProject.bin",
    "xl/vbaProject.bin",
    "ppt/vbaProject.bin",
)
_EMBED_PREFIXES = ("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")


class DOCXExtractor(BaseExtractor):
    def extract(self, path: Path) -> ExtractionResult:
        try:
            import docx  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("python-docx is required: pip install python-docx") from exc

        warnings: list[str] = []
        has_macros = False
        embedded: list[str] = []

        # Inspect ZIP structure first for macros / embeddings
        try:
            with ZipFile(str(path)) as zf:
                names = zf.namelist()
                for mp in _MACRO_PATHS:
                    if mp in names:
                        has_macros = True
                        warnings.append(f"Active content detected: {mp}")
                for name in names:
                    if any(name.startswith(p) for p in _EMBED_PREFIXES):
                        embedded.append(name)
        except BadZipFile as exc:
            warnings.append(f"ZIP read error: {exc}")

        # Extract text
        paragraphs: list[str] = []
        try:
            doc = docx.Document(str(path))
            paragraphs = [p.text for p in doc.paragraphs if p.text.strip()]
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"DOCX text extraction error: {exc}")

        return ExtractionResult(
            text="\n".join(paragraphs),
            page_count=0,  # DOCX has no reliable page count without rendering
            has_macros=has_macros,
            embedded_objects=embedded,
            extraction_warnings=warnings,
        )
