"""Unit tests for text extractors."""
import textwrap
from pathlib import Path

import pytest

from compliance_scan.extractors import extract_text
from compliance_scan.extractors.rtf_extractor import RTFExtractor
from compliance_scan.extractors.txt_extractor import TXTExtractor

FIXTURES = Path(__file__).parent / "fixtures"


class TestTXTExtractor:
    def test_basic_utf8(self, tmp_path):
        f = tmp_path / "sample.txt"
        f.write_text("Hello world\nSecond line", encoding="utf-8")
        result = TXTExtractor().extract(f)
        assert "Hello world" in result.text
        assert result.page_count == 1

    def test_latin1_fallback(self, tmp_path):
        f = tmp_path / "latin.txt"
        f.write_bytes(b"Caf\xe9 au lait")
        result = TXTExtractor().extract(f)
        assert "Caf" in result.text

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.txt"
        f.write_text("", encoding="utf-8")
        result = TXTExtractor().extract(f)
        assert result.text == ""


class TestRTFExtractor:
    def test_basic_rtf(self, tmp_path):
        rtf = textwrap.dedent(r"""
            {\rtf1\ansi\deff0
            {\fonttbl{\f0 Arial;}}
            \f0\fs20 Hello from RTF document\par
            }
        """).strip()
        f = tmp_path / "doc.rtf"
        f.write_text(rtf, encoding="latin-1")
        result = RTFExtractor().extract(f)
        assert "Hello" in result.text


class TestDispatcher:
    def test_txt_dispatch(self, tmp_path):
        f = tmp_path / "file.txt"
        f.write_text("dispatch test", encoding="utf-8")
        result = extract_text(f)
        assert "dispatch test" in result.text

    def test_unknown_extension(self, tmp_path):
        f = tmp_path / "file.xyz"
        f.write_bytes(b"binary")
        result = extract_text(f)
        assert result.extraction_warnings
