"""False-positive suppression for technical/procurement/financial documents.

All patterns are original — no GPL/LGPL code vendored.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Document-type classifiers
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

_FINANCIAL_DOC_SIGNALS: list[str] = [
    r"\bKostenerfassung\b",
    r"\bKostenkalkulation\b",
    r"\bKundenbetreuung\b",
    r"\bStd\.\s*Satz\b",
    r"\bGESAMT-Kosten\b",
    r"\bAbgerechnet\b",
    r"\bDifferenzbetrag\b",
    r"\bGMK\b",
    r"\bReisekosten\b",
    r"\bHotelkosten\b",
    r"\bMietwagenkosten\b",
    r"\bFlugkosten\b",
]
_FINANCIAL_SIGNAL_THRESHOLD = 3


def is_technical_document(text: str) -> bool:
    hits = sum(1 for pat in _TECHNICAL_DOC_SIGNALS if re.search(pat, text, re.IGNORECASE))
    return hits >= _TECHNICAL_SIGNAL_THRESHOLD


def is_financial_document(text: str) -> bool:
    """Return True for internal cost sheets, Kostenkalkulation, timesheets etc."""
    hits = sum(1 for pat in _FINANCIAL_DOC_SIGNALS if re.search(pat, text, re.IGNORECASE))
    return hits >= _FINANCIAL_SIGNAL_THRESHOLD


# ---------------------------------------------------------------------------
# Suppression patterns
# ---------------------------------------------------------------------------

_GLOBAL_SUPPRESSION: list[re.Pattern] = [
    re.compile(r"^(DIN|EN|ISO|VDE|VDI|DIN\s+EN|DIN\s+EN\s+ISO|EN\s+ISO)\s*[\d\-:]+", re.I),
    re.compile(r"^(BGB|WHG|BImSchG|AwSV|AVV|GefStoffV|TRGS|BetrSichV|ArbSchG|NRW|VOB|VOL|HOAI|UVgO)$", re.I),
    re.compile(r"^(CE|EG|EU|EWG|RL)\b"),
    re.compile(r"^\d+[\.,]?\d*\s*(mm|cm|m|km|kg|g|t|kW|MW|kN|MN|bar|Pa|MPa|°C|K|µm|dB|Zoll|\"|%)$", re.I),
    re.compile(r"^\d+[\.,]\d+\s*%$"),
    re.compile(r"^\d{2}\.\d{2}\.\d{4}$"),
    re.compile(r"^(Execution\s+Class|EXC)\s+(I{1,3}|IV|[1-4])$", re.I),
    re.compile(r"^RAL\s*\d{4}$", re.I),
    re.compile(r"^[A-Z0-9]{3,6}[-_][A-Z0-9]{3,10}([-_][A-Z0-9]+)*$"),
    re.compile(r"^(GmbH|AG|KG|OHG|GbR|SE|eV|e\.V\.)$", re.I),
    re.compile(r"^(Germany|Deutschland|Europa|Europe|Berlin|München|Frankfurt|Hamburg|Köln|Stuttgart|Düsseldorf|Mülheim|Essen|Dortmund|Bochum|Duisburg)$", re.I),
    re.compile(r"^(GmbH\s+&\s+Co\.?\s+KG|GmbH\s+&\s+Co\.|Aktiengesellschaft)$", re.I),
    re.compile(r"^[A-Z]{1,4}$"),
    re.compile(r"^[\d\s\-\.]+$"),
    re.compile(r"^v?\d+\.\d+(\.\d+)?$", re.I),
]

_TECHNICAL_SUPPRESSION: list[re.Pattern] = [
    re.compile(r"^(Auftraggeber|Auftragnehmer|Besteller|Lieferant|Projektleiter|Bauleiter|Schweißfachingenieur)$", re.I),
    re.compile(r"^(Montage|Demontage|Inbetriebnahme|Abnahme|Vergabe|Probelauf|Lieferung|Fertigung)$", re.I),
    re.compile(r"^(Anfrage|Angebot|Lastenheft|Pflichtenheft|Leistungsverzeichnis|Protokoll|Zeichnung)$", re.I),
    re.compile(r"^(KP2K|CLP\s*\d+|CGLP\s*\d+|P91|P92|L555|X80|SA\s*[23])$", re.I),
    re.compile(r"^(Siemens|ABB|Bosch|Schneider|Eaton|Phoenix\s+Contact|Wago|Pilz|Beckhoff|Lenze|SEW)$", re.I),
]

# In financial/cost docs: company name fragments and city names are never real PII
_FINANCIAL_SUPPRESSION: list[re.Pattern] = [
    # Short customer/client codes (2-6 uppercase letters)
    re.compile(r"^[A-Z]{2,6}(\s+[A-Z]{2,6})?$"),
    # "Kunde: SMGB", "BWW", "MRM" type tokens
    re.compile(r"^(Kunde|Objekt|Firma|Auftrags|Angebots)$", re.I),
    # City names common in NRW industrial context
    re.compile(r"^(Mülheim|Duisburg|Oberhausen|Gelsenkirchen|Bottrop|Herne|Witten|Remscheid|Solingen|Wuppertal|Krefeld|Mönchengladbach|Neuss|Leverkusen|Aachen|Bonn|Koblenz)$", re.I),
    # SIKOTEC / company name alone
    re.compile(r"^(SIKOTEC|Kostenerfassung|KOSTENERFASSUNG|ORIGINAL|MUSTER)$", re.I),
    # Role/column headers mistaken for names
    re.compile(r"^(Ing|Techn|Kaufm|OM|RM)$", re.I),
]


@dataclass
class PresidioHit:
    entity_type: str
    text: str
    score: float
    start: int
    end: int


# Entities that add no signal in financial cost documents
_FINANCIAL_NOISE_ENTITIES = {"ORGANIZATION", "LOCATION"}


def suppress_false_positives(
    hits: list[PresidioHit],
    text: str,
    is_technical: bool,
    min_score: float = 0.60,
    is_financial: bool | None = None,
) -> list[PresidioHit]:
    """Return filtered list with false positives removed."""
    if is_financial is None:
        is_financial = is_financial_document(text)

    effective_min = (min_score + 0.05) if (is_technical or is_financial) else min_score
    result: list[PresidioHit] = []

    for hit in hits:
        if hit.score < effective_min:
            continue

        snippet = hit.text.strip()

        # In financial docs, ORG/LOC hits are virtually always noise
        if is_financial and hit.entity_type in _FINANCIAL_NOISE_ENTITIES:
            continue

        if any(p.search(snippet) for p in _GLOBAL_SUPPRESSION):
            continue

        if is_technical and any(p.search(snippet) for p in _TECHNICAL_SUPPRESSION):
            continue

        if is_financial and any(p.search(snippet) for p in _FINANCIAL_SUPPRESSION):
            continue

        result.append(hit)

    return result
