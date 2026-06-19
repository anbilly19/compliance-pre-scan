"""XLSX extractor using openpyxl; detects macros in .xlsm files."""
from pathlib import Path
from zipfile import ZipFile, BadZipFile

from .base import BaseExtractor, ExtractionResult

_MACRO_PATHS = ("xl/vbaProject.bin",)


class XLSXExtractor(BaseExtractor):
    def extract(self, path: Path) -> ExtractionResult:
        try:
            import openpyxl  # noqa: PLC0415
        except ImportError as exc:
            raise RuntimeError("openpyxl is required: pip install openpyxl") from exc

        warnings: list[str] = []
        has_macros = False
        cells: list[str] = []

        try:
            with ZipFile(str(path)) as zf:
                for mp in _MACRO_PATHS:
                    if mp in zf.namelist():
                        has_macros = True
                        warnings.append(f"Macro detected: {mp}")
        except BadZipFile as exc:
            warnings.append(f"ZIP read error: {exc}")

        try:
            wb = openpyxl.load_workbook(str(path), read_only=True, data_only=True)
            for sheet in wb.worksheets:
                for row in sheet.iter_rows(values_only=True):
                    for cell in row:
                        if cell is not None:
                            cells.append(str(cell))
            wb.close()
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"XLSX read error: {exc}")

        return ExtractionResult(
            text=" ".join(cells),
            page_count=0,
            has_macros=has_macros,
            extraction_warnings=warnings,
        )
