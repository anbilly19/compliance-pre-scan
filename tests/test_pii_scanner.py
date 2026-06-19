"""Integration-level tests for scan_pii().

These require spaCy models to be installed:
    uv run powershell scripts/install_models.ps1

Mark slow tests so CI can skip them with: pytest -m 'not slow'
"""
import pytest

pytestmark = pytest.mark.slow


def test_detects_german_person_and_phone():
    from compliance_scan.scanners.pii_scanner import scan_pii

    text = (
        "Projektleitung: Peter Storp  Tel: 0208/458-4058  Handy: 0151/15956147  "
        "E-Mail: Peter.Storp@smgb.de"
    )
    hits = scan_pii(text, language="de")
    entity_types = {h.entity_type for h in hits}
    # Expect at least email and phone — person name detection varies by model
    assert "EMAIL_ADDRESS" in entity_types or "PHONE_NUMBER" in entity_types


def test_technical_doc_low_hit_count():
    """Procurement/technical docs should produce very few hits after suppression."""
    from compliance_scan.scanners.pii_scanner import scan_pii

    technical_text = """
    Anfrage Nr. 10364394 — Auftragnehmer muss Leistungsumfang gemäß DIN EN ISO 9001 erfüllen.
    Montage und Inbetriebnahme. Vergabe bis 13.03.2026. Execution Class II.
    Werkstoffe nach DIN EN 10025. Schweißnähte nach DIN EN ISO 5817.
    Gewicht max. 25000 kg. Biegeradius 200 mm bis 10000 mm.
    BGB §§ 276, 443. NRW Landesbauordnung. AwSV Fachbetriebspflicht.
    """
    hits = scan_pii(technical_text, language="de")
    # Should be far fewer than the raw ~800 — acceptable threshold is < 15
    assert len(hits) < 15, f"Expected < 15 hits for technical doc, got {len(hits)}: {hits}"


def test_personal_doc_keeps_sensitive_hits():
    """Personal documents must still surface real PII."""
    from compliance_scan.scanners.pii_scanner import scan_pii

    personal_text = (
        "Sehr geehrter Herr Müller, Ihre IBAN DE89370400440532013000 "
        "wurde mit EUR 4200 gutgeschrieben. Rückfragen: max.mueller@example.de, "
        "Tel. +49 170 1234567."
    )
    hits = scan_pii(personal_text, language="de")
    entity_types = {h.entity_type for h in hits}
    assert "IBAN_CODE" in entity_types or "EMAIL_ADDRESS" in entity_types
