"""Keyword/phrase scanner backed by a YAML config file.

The YAML config supports two modes:
  - plain string keywords (case-insensitive, whole-word match)
  - regex patterns (prefixed with 're:')

Example keywords.yml:
  categories:
    - name: confidential_labels
      severity: HIGH
      terms:
        - STRICTLY CONFIDENTIAL
        - re:Geheimhaltungsvereinbarung
        - NDA
    - name: financial
      severity: MEDIUM
      terms:
        - IBAN
        - Kontonummer
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from ..audit.models import RuleHit


@dataclass
class _Category:
    name: str
    severity: str
    patterns: list[re.Pattern] = field(default_factory=list)


_BUILTIN_CATEGORIES: list[_Category] = [
    _Category(
        name="confidential_labels",
        severity="HIGH",
        patterns=[
            re.compile(r"\bSTRICTLY CONFIDENTIAL\b", re.IGNORECASE),
            re.compile(r"\bCONFIDENTIAL\b", re.IGNORECASE),
            re.compile(r"\bINTERNAL ONLY\b", re.IGNORECASE),
            re.compile(r"\bNUR F.R DEN INTERNEN GEBRAUCH\b", re.IGNORECASE),
            re.compile(r"\bGeheimhaltungsvereinbarung\b", re.IGNORECASE),
            re.compile(r"\bVertraulich\b", re.IGNORECASE),
            re.compile(r"\bNDA\b"),
        ],
    ),
    _Category(
        name="betriebsrat_sensitive",
        severity="HIGH",
        patterns=[
            re.compile(r"\bBetriebsrat\b", re.IGNORECASE),
            re.compile(r"\bPersonalakte\b", re.IGNORECASE),
            re.compile(r"\bAbmahnung\b", re.IGNORECASE),
            re.compile(r"\bGehaltsverhandlung\b", re.IGNORECASE),
        ],
    ),
    _Category(
        name="legal_contracts",
        severity="MEDIUM",
        patterns=[
            re.compile(r"\bEVB-IT\b", re.IGNORECASE),
            re.compile(r"\bAuftragsverarbeitungsvertrag\b", re.IGNORECASE),
            re.compile(r"\bDatenverarbeitungsvertrag\b", re.IGNORECASE),
        ],
    ),
]


def _compile_term(term: str) -> re.Pattern:
    if term.startswith("re:"):
        return re.compile(term[3:], re.IGNORECASE)
    return re.compile(r"\b" + re.escape(term) + r"\b", re.IGNORECASE)


class KeywordScanner:
    def __init__(self, config_paths: list[Path] | None = None) -> None:
        self._categories: list[_Category] = list(_BUILTIN_CATEGORIES)
        for p in (config_paths or []):
            self._load_yaml(p)

    def _load_yaml(self, path: Path) -> None:
        if not path.exists():
            return
        with path.open(encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        for cat in data.get("categories", []):
            c = _Category(
                name=cat["name"],
                severity=cat.get("severity", "MEDIUM"),
                patterns=[_compile_term(t) for t in cat.get("terms", [])],
            )
            self._categories.append(c)

    def scan(self, text: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for cat in self._categories:
            for pattern in cat.patterns:
                for m in pattern.finditer(text):
                    hits.append(RuleHit(
                        scanner="KEYWORD",
                        rule_id=f"{cat.name}:{pattern.pattern}",
                        entity_type=cat.name,
                        severity=cat.severity,
                        offset_char=m.start(),
                        match_snippet=m.group(0)[:80],
                    ))
        return hits
