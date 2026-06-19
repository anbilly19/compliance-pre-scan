"""Lightweight language detection for scan pipeline.

Uses langdetect (MIT) to determine primary language of extracted text.
Falls back to 'en' on any error or if text is too short to be reliable.

Supported scanner languages: 'en', 'de'.
All other detected languages fall back to 'en' for Presidio.
"""
from __future__ import annotations

import logging

log = logging.getLogger(__name__)

_SUPPORTED = {"en", "de"}
_MIN_CHARS = 60  # below this, detection is unreliable


def detect_language(text: str) -> str:
    """Return 'en' or 'de'. Never raises."""
    if not text or len(text.strip()) < _MIN_CHARS:
        return "en"
    try:
        from langdetect import detect, DetectorFactory
        DetectorFactory.seed = 0  # deterministic
        lang = detect(text)
        if lang in _SUPPORTED:
            return lang
        log.debug("Detected language '%s' not in supported set — falling back to 'en'", lang)
        return "en"
    except Exception as exc:
        log.debug("Language detection failed (%s) — defaulting to 'en'", exc)
        return "en"
