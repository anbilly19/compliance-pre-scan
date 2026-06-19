from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class ExtractionResult:
    """Output from any extractor."""
    text: str                        # full extracted plain text
    page_count: int = 0              # number of pages/sheets (0 if N/A)
    char_count: int = 0              # character count of extracted text
    raw_byte_size: int = 0           # original file size in bytes
    has_macros: bool = False         # True if active macros / VBA detected
    has_embedded_objects: bool = False  # True if OLE or embedded files found
    metadata: dict = field(default_factory=dict)  # any extractor-specific extras

    def __post_init__(self):
        self.char_count = len(self.text)


class BaseExtractor(ABC):
    """All file-type extractors implement this interface."""

    @abstractmethod
    def extract(self, data: bytes, filename: str) -> ExtractionResult:
        """
        Extract plain text and metadata from raw file bytes.

        Args:
            data:     raw file bytes
            filename: original filename (used for logging only)

        Returns:
            ExtractionResult
        """
        ...
