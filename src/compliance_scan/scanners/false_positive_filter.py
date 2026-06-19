"""False-positive suppression for technical/procurement documents.

All patterns are original — no GPL/LGPL code vendored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Document-type classifier
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

_TECHNICAL_SIGNAL_THRESHOLD = 4


def is_technical_document(text: str) -> bool:
    hits = sum(1 for pat in _TECHNICAL_DOC_SIGNALS if re.search(pat, text, re.IGNORECASE))
    return hits >= _TECHNICAL_SIGNAL_THRESHOLD


# ---------------------------------------------------------------------------
# Suppression patterns
# ---------------------------------------------------------------------------

# Always suppressed
_GLOBAL_SUPPRESSION: list[re.Pattern] = [
    # DIN / EN / ISO standards
    re.compile(r"^(DIN|EN|ISO|VDE|VDI|DIN\s+EN|DIN\s+EN\s+ISO|EN\s+ISO)\s*[\d\-:]+", re.I),
    # Legal abbreviations
    re.compile(r"^(BGB|WHG|BImSchG|AwSV|AVV|GefStoffV|TRGS|BetrSichV|ArbSchG|NRW|VOB|VOL|HOAI|UVgO)$", re.I),
    # EU/CE markings
    re.compile(r"^(CE|EG|EU|EWG|RL)\b"),
    # Measurements
    re.compile(r"^\d+[\.,]?\d*\s*(mm|cm|m|km|kg|g|t|kW|MW|kN|MN|bar|Pa|MPa|°C|K|µm|dB|Zoll|\"|%)$", re.I),
    # Percentage
    re.compile(r"^\d+[\.,]\d+\s*%$"),
    # German dates
    re.compile(r"^\d{2}\.\d{2}\.\d{4}$"),
    # Execution class
    re.compile(r"^(Execution\s+Class|EXC)\s+(I{1,3}|IV|[1-4])$", re.I),
    # RAL colours
    re.compile(r"^RAL\s*\d{4}$", re.I),
    # Part / drawing numbers
    re.compile(r"^[A-Z0-9]{3,6}[-_][A-Z0-9]{3,10}([-_][A-Z0-9]+)*$"),
    # Company suffixes alone
    re.compile(r"^(GmbH|AG|KG|OHG|GbR|SE|eV|e\.V\.)$", re.I),
    # Single-word generic LOCATION hits: city names that are also common nouns
    re.compile(r"^(Germany|Deutschland|Europa|Europe|Berlin|München|Frankfurt|Hamburg|Köln|Stuttgart|Düsseldorf)$", re.I),
    # Generic org tokens
    re.compile(r"^(GmbH\s+&\s+Co\.?\s+KG|GmbH\s+&\s+Co\.|Aktiengesellschaft)$", re.I),
    # Short all-caps abbreviations (4 chars or fewer) — rarely real PII
    re.compile(r"^[A-Z]{1,4}$"),
    # Pure numbers (Presidio sometimes tags these as PERSON via NER)
    re.compile(r"^[\d\s\-\.]+$"),
    # Version strings
    re.compile(r"^v?\d+\.\d+(\.\d+)?$", re.I),
]

# Only applied for technical/procurement documents
_TECHNICAL_SUPPRESSION: list[re.Pattern] = [
    re.compile(r"^(Auftraggeber|Auftragnehmer|Besteller|Lieferant|Projektleiter|Bauleiter|Schweißfachingenieur)$", re.I),
    re.compile(r"^(Montage|Demontage|Inbetriebnahme|Abnahme|Vergabe|Probelauf|Lieferung|Fertigung)$", re.I),
    re.compile(r"^(Anfrage|Angebot|Lastenheft|Pflichtenheft|Leistungsverzeichnis|Protokoll|Zeichnung)$", re.I),
    re.compile(r"^(KP2K|CLP\s*\d+|CGLP\s*\d+|P91|P92|L555|X80|SA\s*[23])$", re.I),
    # Organisation hits that are product/brand names in technical context
    re.compile(r"^(Siemens|ABB|Bosch|Schneider|Eaton|Phoenix Contact|Wago|Pilz|Beckhoff|Lenze|SEW)$", re.I),
]


@dataclass
class PresidioHit:
    entity_type: str
    text: str
    score: float
    start: int
    end: int


def suppress_false_positives(
    hits: list[PresidioHit],
    text: str,
    is_technical: bool,
    min_score: float = 0.60,
) -> list[PresidioHit]:
    effective_min = (min_score + 0.05) if is_technical else min_score
    result: list[PresidioHit] = []

    for hit in hits:
        if hit.score < effective_min:
            continue
        snippet = hit.text.strip()
        if any(p.search(snippet) for p in _GLOBAL_SUPPRESSION):
            continue
        if is_technical and any(p.search(snippet) for p in _TECHNICAL_SUPPRESSION):
            continue
        result.append(hit)

    return result
