"""PII scanner using Microsoft Presidio with bilingual support (EN + DE).

German spaCy model: de_core_news_md  (MIT / CC-BY-SA-3.0)
English spaCy model: en_core_web_md  (MIT)
Presidio: MIT
langdetect: Apache-2.0
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from functools import lru_cache

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
    "EMAIL_ADDRESS", "PHONE_NUMBER",
}
_LOW_SEVERITY_ENTITIES = {"DATE_TIME", "NRP"}


def _entity_severity(entity_type: str) -> str:
    if entity_type in _HIGH_SEVERITY_ENTITIES:
        return "HIGH"
    if entity_type in _LOW_SEVERITY_ENTITIES:
        return "LOW"
    return "MEDIUM"


def _mask_snippet(text: str) -> str:
    t = text.strip()
    if len(t) <= 4:
        return "**"
    return t[:2] + "***" + t[-2:]


@lru_cache(maxsize=None)
def _get_analyzer(language: str):
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    model_map = {"en": "en_core_web_md", "de": "de_core_news_md"}
    spacy_model = model_map.get(language, "en_core_web_md")
    provider = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": language, "model_name": spacy_model}],
        }
    )
    nlp_engine = provider.create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[language])
    log.info("Presidio loaded lang='%s' model='%s'", language, spacy_model)
    return analyzer


_REGEX_ENTITIES = ["EMAIL_ADDRESS", "PHONE_NUMBER", "IBAN_CODE", "CREDIT_CARD", "IP_ADDRESS"]
_NER_ENTITIES   = ["PERSON", "LOCATION", "ORGANIZATION"]
_ALL_ENTITIES   = _REGEX_ENTITIES + _NER_ENTITIES

_REGEX_MIN_SCORE = 0.60
_NER_MIN_SCORE   = 0.85
_TECHNICAL_BUMP  = 0.05


def scan_pii(
    text: str,
    language: str | None = None,
    entities: list[str] | None = None,
    min_score: float = _REGEX_MIN_SCORE,
) -> list[PIIMatch]:
    """Scan text for PII and return deduplicated, filtered matches."""
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
    entity_list = entities or _ALL_ENTITIES

    log.debug(
        "scan_pii start — lang='%s' is_technical=%s entities=%s",
        lang, is_technical, entity_list,
    )

    try:
        analyzer = _get_analyzer(lang)
    except Exception as exc:
        log.warning("Analyzer load failed lang='%s': %s — fallback to 'en'", lang, exc)
        analyzer = _get_analyzer("en")
        lang = "en"

    bump = _TECHNICAL_BUMP if is_technical else 0.0

    try:
        raw_results = analyzer.analyze(
            text=text,
            entities=entity_list,
            language=lang,
            score_threshold=_REGEX_MIN_SCORE - 0.05,
        )
    except Exception as exc:
        log.error("Presidio analysis failed: %s", exc)
        return []

    log.debug("Presidio raw hits: %d", len(raw_results))

    # Per-entity-type score gate
    filtered_raw = []
    for r in raw_results:
        threshold = (_NER_MIN_SCORE if r.entity_type in _NER_ENTITIES else _REGEX_MIN_SCORE) + bump
        if r.score >= threshold:
            filtered_raw.append(r)
        else:
            log.debug(
                "  DROPPED score=%.2f < %.2f  entity=%s  snippet=%r",
                r.score, threshold, r.entity_type, text[r.start:r.end][:40],
            )

    log.debug("After score gate: %d hits", len(filtered_raw))

    hits = [
        PresidioHit(
            entity_type=r.entity_type,
            text=text[r.start:r.end],
            score=r.score,
            start=r.start,
            end=r.end,
        )
        for r in filtered_raw
    ]

    filtered = suppress_false_positives(
        hits, text, is_technical=is_technical, min_score=_REGEX_MIN_SCORE
    )

    log.debug("After FP suppression: %d hits", len(filtered))
    for h in filtered:
        log.debug(
            "  KEPT entity=%s score=%.2f snippet=%r",
            h.entity_type, h.score, h.text[:40],
        )

    # Deduplicate by span
    seen: dict[tuple[int, int], PresidioHit] = {}
    for h in filtered:
        key = (h.start, h.end)
        if key not in seen or h.score > seen[key].score:
            seen[key] = h

    log.debug("Final deduplicated hits: %d", len(seen))

    return [
        PIIMatch(
            entity_type=h.entity_type,
            text=h.text,
            score=h.score,
            start=h.start,
            end=h.end,
        )
        for h in seen.values()
    ]


class PIIScanner:
    """Pipeline-compatible class wrapper around scan_pii."""

    def __init__(
        self,
        entities: list[str] | None = None,
        min_score: float = _REGEX_MIN_SCORE,
    ) -> None:
        self._entities = entities
        self._min_score = min_score

    def scan(self, text: str, language: str | None = None) -> list[RuleHit]:
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
