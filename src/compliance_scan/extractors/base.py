"""Shared interface every extractor must implement."""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ExtractionResult:
    text: str = ""
    page_count: int = 0
    has_macros: bool = False
    embedded_objects: list[str] = field(default_factory=list)  # object types found
    extraction_warnings: list[str] = field(default_factory=list)


class BaseExtractor(ABC):
    @abstractmethod
    def extract(self, path: Path) -> ExtractionResult:
        """Return extracted text and structural metadata."""
