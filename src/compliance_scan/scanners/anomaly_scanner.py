"""Anomaly / malicious-content heuristics.

Checks (all local, no external calls):
  1. Extension vs MIME mismatch          -> EXTENSION_MISMATCH
  2. Suspiciously high binary-to-text ratio  -> SIZE_TEXT_RATIO
  3. Shannon entropy of raw bytes        -> HIGH_ENTROPY
  4. Active content in docs (macros/OLE) -> ACTIVE_CONTENT
  5. Embedded objects in OOXML           -> EMBEDDED_OBJECTS
"""
from __future__ import annotations

import math
from collections import Counter
from pathlib import Path

from ..audit.models import RuleHit
from ..config import settings
from .file_identity import FileIdentity
from ..extractors.base import ExtractionResult


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


class AnomalyScanner:
    def scan(
        self,
        path: Path,
        identity: FileIdentity,
        extraction: ExtractionResult,
    ) -> list[RuleHit]:
        hits: list[RuleHit] = []

        # 1. Extension / MIME mismatch
        if identity.extension_mismatch:
            hits.append(RuleHit(
                scanner="ANOMALY",
                rule_id="EXTENSION_MISMATCH",
                severity="HIGH",
                match_snippet=(
                    f"declared={identity.mime_from_extension!r} "
                    f"detected={identity.mime_detected!r}"
                )[:80],
            ))

        # 2. Size vs. text content ratio
        file_size = path.stat().st_size
        text_len = len(extraction.text)
        if text_len > 0:
            ratio = file_size / text_len
            if ratio > settings.size_ratio_threshold:
                hits.append(RuleHit(
                    scanner="ANOMALY",
                    rule_id="SIZE_TEXT_RATIO",
                    severity="MEDIUM",
                    match_snippet=f"ratio={ratio:.1f} (threshold={settings.size_ratio_threshold})",
                ))

        # 3. Shannon entropy
        try:
            raw = path.read_bytes()
            # Sample up to first 64 KB for performance
            entropy = _shannon_entropy(raw[:65536])
            if entropy > settings.entropy_high_threshold:
                hits.append(RuleHit(
                    scanner="ANOMALY",
                    rule_id="HIGH_ENTROPY",
                    severity="MEDIUM",
                    match_snippet=f"entropy={entropy:.3f} bits/byte (threshold={settings.entropy_high_threshold})",
                ))
        except OSError:
            pass

        # 4. Active content (macros)
        if extraction.has_macros:
            hits.append(RuleHit(
                scanner="ANOMALY",
                rule_id="ACTIVE_CONTENT",
                severity="HIGH",
                match_snippet="Document contains VBA macros or active content.",
            ))

        # 5. Embedded objects
        if extraction.embedded_objects:
            hits.append(RuleHit(
                scanner="ANOMALY",
                rule_id="EMBEDDED_OBJECTS",
                severity="MEDIUM",
                match_snippet=f"Embedded objects: {', '.join(extraction.embedded_objects[:5])}",
            ))

        return hits
