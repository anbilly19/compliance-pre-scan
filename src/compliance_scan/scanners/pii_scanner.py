"""PII detection using Microsoft Presidio Analyzer (regex + optional NLP)."""
from __future__ import annotations

from ..audit.models import RuleHit

# Default entity set (extendable via config)
_DEFAULT_ENTITIES = [
    "PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER",
    "IBAN_CODE", "CREDIT_CARD",
    "IP_ADDRESS", "URL",
    "DATE_TIME",
    "NRP",          # Nationality / Religion / Political opinion
    "LOCATION",
    "MEDICAL_LICENSE",
    "US_SSN", "US_PASSPORT",
    "DE_TAX_IDENTIFICATION_NUMBER",  # German Steueridentifikationsnummer
    "DE_PASSPORT",
]

_SEVERITY_MAP: dict[str, str] = {
    "PERSON": "MEDIUM",
    "EMAIL_ADDRESS": "MEDIUM",
    "PHONE_NUMBER": "MEDIUM",
    "IBAN_CODE": "HIGH",
    "CREDIT_CARD": "HIGH",
    "US_SSN": "HIGH",
    "DE_TAX_IDENTIFICATION_NUMBER": "HIGH",
    "DE_PASSPORT": "HIGH",
    "US_PASSPORT": "HIGH",
    "MEDICAL_LICENSE": "HIGH",
}


class PIIScanner:
    """Wraps Presidio AnalyzerEngine; lazy-initialises on first call."""

    def __init__(self, entities: list[str] | None = None) -> None:
        self._entities = entities or _DEFAULT_ENTITIES
        self._engine = None  # lazily initialised

    def _get_engine(self):
        if self._engine is None:
            try:
                from presidio_analyzer import AnalyzerEngine  # noqa: PLC0415
                self._engine = AnalyzerEngine()
            except ImportError as exc:
                raise RuntimeError(
                    "presidio-analyzer is required: pip install presidio-analyzer"
                ) from exc
        return self._engine

    def scan(self, text: str, language: str = "en") -> list[RuleHit]:
        """Return PII hits found in *text*."""
        if not text.strip():
            return []

        engine = self._get_engine()
        try:
            results = engine.analyze(
                text=text,
                entities=self._entities,
                language=language,
            )
        except Exception as exc:  # noqa: BLE001
            return [RuleHit(
                scanner="PII",
                rule_id="PRESIDIO_ERROR",
                severity="LOW",
                match_snippet=str(exc)[:80],
            )]

        hits: list[RuleHit] = []
        for r in results:
            snippet = text[r.start : r.end]
            # Mask middle characters: keep first 2 and last 2 only
            if len(snippet) > 6:
                masked = snippet[:2] + "*" * (len(snippet) - 4) + snippet[-2:]
            else:
                masked = "****"

            hits.append(RuleHit(
                scanner="PII",
                rule_id=r.entity_type,
                entity_type=r.entity_type,
                severity=_SEVERITY_MAP.get(r.entity_type, "MEDIUM"),
                offset_char=r.start,
                match_snippet=masked,
            ))

        return hits
