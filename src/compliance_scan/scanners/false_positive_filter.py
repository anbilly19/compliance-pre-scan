"""False-positive suppression for technical/procurement documents.

Filters out Presidio hits that match known non-sensitive patterns common in
German industrial, legal, and procurement texts (DIN/EN/ISO standards,
legal abbreviations, measurements, etc.).

All patterns are original — no GPL/LGPL code vendored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

# ---------------------------------------------------------------------------
# Document-type classifier — detects technical/procurement documents
# ---------------------------------------------------------------------------

_TECHNICAL_DOC_SIGNALS: list[str] = [
    r"\bAuftragnehmer\b",
    r"\bLeistungsumfang\b",
    r"\bAusschreibung\b",
    r"\bAnfrage\b",
    r"\bAngebot\b",
    r"\bLieferumfang\b",
    r"\bMontage\b",
    r"\bInbetriebnahme\b",
    r"\bDIN\s+EN\b",
    r"\bAuftraggeber\b",
    r"\bLeistungsverzeichnis\b",
    r"\bVergabe\b",
]

_TECHNICAL_SIGNAL_THRESHOLD = 4  # need at least 4 distinct signals to classify as technical


def is_technical_document(text: str) -> bool:
    """Return True if text looks like a technical specification or procurement doc."""
    hits = sum(1 for pat in _TECHNICAL_DOC_SIGNALS if re.search(pat, text, re.IGNORECASE))
    return hits >= _TECHNICAL_SIGNAL_THRESHOLD


# ---------------------------------------------------------------------------
# Suppression patterns — matched against the *snippet* of a Presidio hit
# ---------------------------------------------------------------------------

# Patterns that are NEVER sensitive regardless of doc type
_GLOBAL_SUPPRESSION: list[re.Pattern] = [
    # DIN / EN / ISO / VDE / VDI standard references
    re.compile(r"^(DIN|EN|ISO|VDE|VDI|DIN\s+EN|DIN\s+EN\s+ISO|EN\s+ISO)\s*[\d\-:]+", re.I),
    # German legal abbreviations
    re.compile(r"^(BGB|WHG|BImSchG|AwSV|AVV|GefStoffV|TRGS|BetrSichV|ArbSchG|NRW|VOB|VOL|HOAI|UVgO)$", re.I),
    # EU/CE marking references
    re.compile(r"^(CE|EG|EU|EWG|RL)\b"),
    # Measurement values (numbers with units)
    re.compile(r"^\d+[\.,]?\d*\s*(mm|cm|m|km|kg|g|t|kW|MW|kN|MN|bar|Pa|MPa|°C|K|µm|dB|Zoll|\"|%)$", re.I),
    # Percentage / ratio alone
    re.compile(r"^\d+[\.,]\d+\s*%$"),
    # Pure date strings (DE format)
    re.compile(r"^\d{2}\.\d{2}\.\d{4}$"),
    # Execution class references
    re.compile(r"^(Execution\s+Class|EXC)\s+(I{1,3}|IV|[1-4])$", re.I),
    # RAL colour codes
    re.compile(r"^RAL\s*\d{4}$", re.I),
    # Drawing / order numbers (pure numeric or alphanumeric codes)
    re.compile(r"^[A-Z0-9]{3,6}[-_][A-Z0-9]{3,10}([-_][A-Z0-9]+)*$"),
    # Common German company-name suffixes alone
    re.compile(r"^(GmbH|AG|KG|OHG|GbR|SE|eV|e\.V\.)$", re.I),
]

# Additional suppression applied only for technical/procurement documents
_TECHNICAL_SUPPRESSION: list[re.Pattern] = [
    # Generic role titles (not personal names)
    re.compile(r"^(Auftraggeber|Auftragnehmer|Besteller|Lieferant|Projektleiter|Bauleiter|Schweißfachingenieur)$", re.I),
    # Project phases and actions
    re.compile(r"^(Montage|Demontage|Inbetriebnahme|Abnahme|Vergabe|Probelauf|Lieferung|Fertigung)$", re.I),
    # Technical document types
    re.compile(r"^(Anfrage|Angebot|Lastenheft|Pflichtenheft|Leistungsverzeichnis|Protokoll|Zeichnung)$", re.I),
    # Schmierstoff / material grade tokens
    re.compile(r"^(KP2K|CLP\s*\d+|CGLP\s*\d+|P91|P92|L555|X80|SA\s*[23])$", re.I),
]


@dataclass
class PresidioHit:
    entity_type: str
    text: str          # matched snippet
    score: float
    start: int
    end: int


def suppress_false_positives(
    hits: list[PresidioHit],
    text: str,
    is_technical: bool,
    min_score: float = 0.65,
) -> list[PresidioHit]:
    """Return filtered list with false positives removed.

    Args:
        hits: Raw Presidio results wrapped as PresidioHit.
        text: Full document text (used for context checks).
        is_technical: Whether the document was classified as technical.
        min_score: Minimum Presidio confidence to keep.  For technical docs
            this is raised automatically.
    """
    effective_min = (min_score + 0.10) if is_technical else min_score
    result: list[PresidioHit] = []

    for hit in hits:
        # Score threshold
        if hit.score < effective_min:
            continue

        snippet = hit.text.strip()

        # Global suppression
        if any(p.search(snippet) for p in _GLOBAL_SUPPRESSION):
            continue

        # Technical-document suppression
        if is_technical and any(p.search(snippet) for p in _TECHNICAL_SUPPRESSION):
            continue

        result.append(hit)

    return result
