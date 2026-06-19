"""Tests for false_positive_filter — ensures technical docs suppress noise."""
import pytest
from compliance_scan.scanners.false_positive_filter import (
    PresidioHit,
    is_technical_document,
    suppress_false_positives,
)

_TECHNICAL_TEXT = """
Anfrage Nr. 12345 — Auftragnehmer muss Leistungsumfang gemäß DIN EN ISO 9001 erfüllen.
Montage und Inbetriebnahme durch den Auftraggeber. Vergabe bis 13.03.2026.
Leistungsverzeichnis liegt bei. Lieferumfang umfasst alle Teile.
"""

_PERSONAL_TEXT = """
Dear John Smith, please find attached your salary slip for March 2026.
Your IBAN DE89370400440532013000 has been credited with EUR 4200.
Contact: john.smith@example.com, Tel: +49 151 12345678
"""


def _make_hit(entity_type: str, text: str, score: float = 0.80) -> PresidioHit:
    return PresidioHit(entity_type=entity_type, text=text, score=score, start=0, end=len(text))


class TestIsTechnicalDocument:
    def test_detects_procurement_doc(self):
        assert is_technical_document(_TECHNICAL_TEXT) is True

    def test_rejects_personal_doc(self):
        assert is_technical_document(_PERSONAL_TEXT) is False


class TestSuppressFalsePositives:
    def test_din_standard_suppressed_globally(self):
        hits = [_make_hit("ORGANIZATION", "DIN EN ISO 9001")]
        result = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=False)
        assert result == []

    def test_measurement_suppressed_globally(self):
        hits = [_make_hit("QUANTITY", "25000 kg")]
        result = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=False)
        assert result == []

    def test_legal_abbrev_suppressed_globally(self):
        for abbrev in ["BGB", "NRW", "AwSV", "BImSchG"]:
            hits = [_make_hit("ORGANIZATION", abbrev)]
            result = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=False)
            assert result == [], f"{abbrev} should be suppressed"

    def test_role_title_suppressed_in_technical_doc(self):
        hits = [_make_hit("PERSON", "Auftragnehmer")]
        result = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=True)
        assert result == []

    def test_real_person_name_kept_in_technical_doc(self):
        # A real name should survive even in a technical doc
        hits = [_make_hit("PERSON", "Peter Storp", score=0.85)]
        result = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=True)
        assert len(result) == 1

    def test_iban_kept_in_personal_doc(self):
        hits = [_make_hit("IBAN_CODE", "DE89370400440532013000", score=0.95)]
        result = suppress_false_positives(hits, _PERSONAL_TEXT, is_technical=False)
        assert len(result) == 1

    def test_low_score_filtered(self):
        hits = [_make_hit("PERSON", "Peter Storp", score=0.50)]
        result = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=False, min_score=0.65)
        assert result == []

    def test_technical_doc_raises_effective_threshold(self):
        # score=0.70 passes for non-technical but fails for technical (threshold raised by 0.10)
        hits = [_make_hit("PERSON", "Peter Storp", score=0.70)]
        non_tech = suppress_false_positives(hits, _PERSONAL_TEXT, is_technical=False, min_score=0.65)
        technical = suppress_false_positives(hits, _TECHNICAL_TEXT, is_technical=True, min_score=0.65)
        assert len(non_tech) == 1
        assert len(technical) == 0
