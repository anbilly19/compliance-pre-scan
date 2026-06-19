"""PII scanner using Microsoft Presidio with bilingual support (EN + DE).

Loads both English and German NLP models.  Language is auto-detected per
document via detect_language().  False positives are suppressed via
false_positive_filter before results are returned.

German spaCy model: de_core_news_md  (MIT / CC-BY-SA-3.0)
English spaCy model: en_core_web_md  (MIT)
Presidio: MIT
langdetect: Apache-2.0
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from functools import lru_cache
from typing import List

from ..audit.models import RuleHit

log = logging.getLogger(__name__)


@dataclass
class PIIMatch:
    entity_type: str
    text: str
    score: float
    start: int
    end: int
    severity: str = "MEDIUM"
    match_snippet: str = ""

    def __post_init__(self) -> None:
        self.match_snippet = _mask_snippet(self.text)
        self.severity = _entity_severity(self.entity_type)


_HIGH_SEVERITY_ENTITIES = {
    "CREDIT_CARD", "IBAN_CODE", "MEDICAL_LICENSE",
    "US_SSN", "US_PASSPORT", "US_DRIVER_LICENSE",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
}

_LOW_SEVERITY_ENTITIES = {
    "DATE_TIME", "NRP",
}


def _entity_severity(entity_type: str) -> str:
    if entity_type in _HIGH_SEVERITY_ENTITIES:
        return "HIGH"
    if entity_type in _LOW_SEVERITY_ENTITIES:
        return "LOW"
    return "MEDIUM"


def _mask_snippet(text: str) -> str:
    """Return first 2 + last 2 chars with middle masked, max 12 chars shown."""
    t = text.strip()
    if len(t) <= 4:
        return "**"
    return t[:2] + "***" + t[-2:]


# ---------------------------------------------------------------------------
# Lazy-loaded Presidio engines (one per language)
# ---------------------------------------------------------------------------

@lru_cache(maxsize=None)
def _get_analyzer(language: str):
    """Return a cached PresidioAnalyzerEngine for the given language."""
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    model_map = {
        "en": "en_core_web_md",
        "de": "de_core_news_md",
    }
    spacy_model = model_map.get(language, "en_core_web_md")

    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": spacy_model}],
        }
    )
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[language])
    log.info("Presidio AnalyzerEngine loaded for language='%s' model='%s'", language, spacy_model)
    return analyzer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_ENTITIES = [
    "PERSON",
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IBAN_CODE",
    "CREDIT_CARD",
    "LOCATION",
    "DATE_TIME",
    "ORGANIZATION",
    "IP_ADDRESS",
    "URL",
    "NRP",
]


def scan_pii(
    text: str,
    language: str | None = None,
    entities: list[str] | None = None,
    min_score: float = 0.65,
) -> list[PIIMatch]:
    """Scan text for PII and return filtered matches."""
    if not text or not text.strip():
        return []

    from .language_detect import detect_language
    from .false_positive_filter import (
        PresidioHit,
        is_technical_document,
        suppress_false_positives,
    )

    lang = language or detect_language(text)
    is_technical = is_technical_document(text)

    if is_technical:
        log.debug("Document classified as TECHNICAL — raising suppression thresholds")

    try:
        analyzer = _get_analyzer(lang)
    except Exception as exc:
        log.warning(
            "Failed to load Presidio analyzer for lang='%s': %s — falling back to 'en'",
            lang, exc,
        )
        analyzer = _get_analyzer("en")
        lang = "en"

    try:
        raw_results = analyzer.analyze(
            text=text,
            entities=entities or _DEFAULT_ENTITIES,
            language=lang,
            score_threshold=min_score,
        )
    except Exception as exc:
        log.error("Presidio analysis failed: %s", exc)
        return []

    from .false_positive_filter import PresidioHit, suppress_false_positives

    hits = [
        PresidioHit(
            entity_type=r.entity_type,
            text=text[r.start:r.end],
            score=r.score,
            start=r.start,
            end=r.end,
        )
        for r in raw_results
    ]

    filtered = suppress_false_positives(hits, text, is_technical=is_technical, min_score=min_score)

    return [
        PIIMatch(
            entity_type=h.entity_type,
            text=h.text,
            score=h.score,
            start=h.start,
            end=h.end,
        )
        for h in filtered
    ]


class PIIScanner:
    """Stateless class wrapper around scan_pii for use in the pipeline."""

    def __init__(
        self,
        entities: list[str] | None = None,
        min_score: float = 0.65,
    ) -> None:
        self._entities = entities
        self._min_score = min_score

    def scan(self, text: str, language: str | None = None) -> list[RuleHit]:
        """Run PII scan and return RuleHit list compatible with pipeline."""
        matches = scan_pii(
            text,
            language=language,
            entities=self._entities,
            min_score=self._min_score,
        )
        return [
            RuleHit(
                scanner="PII",
                rule_id=f"PII:{m.entity_type}",
                entity_type=m.entity_type,
                severity=m.severity,
                offset_char=m.start,
                match_snippet=m.match_snippet,
            )
            for m in matches
        ]
