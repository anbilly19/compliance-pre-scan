"""Anomaly / malicious-content heuristics.

Checks (all local, no external calls):
  1. Extension vs MIME mismatch          -> EXTENSION_MISMATCH
  2. Suspiciously high binary-to-text ratio  -> SIZE_TEXT_RATIO
  3. Shannon entropy of raw bytes        -> HIGH_ENTROPY
  4. Active content in docs (macros/OLE) -> ACTIVE_CONTENT
  5. Embedded objects in OOXML           -> EMBEDDED_OBJECTS
  6. Archive recursion depth (ZIP bomb)  -> ARCHIVE_BOMB
"""
from __future__ import annotations

import io
import math
import zipfile
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


def _max_zip_depth(data: bytes, current_depth: int, limit: int) -> int:
    """Recursively measure the deepest nesting level of ZIPs.

    Reads ZIP entries from *data* in-memory.  If any entry is itself a ZIP,
    recurse.  Stops early once depth exceeds *limit* to avoid wasting time.
    Returns the maximum depth reached (1 = single ZIP with no nested ZIPs).
    """
    if current_depth > limit:
        return current_depth

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            max_depth = current_depth
            for info in zf.infolist():
                name_lower = info.filename.lower()
                if name_lower.endswith(".zip"):
                    try:
                        nested_bytes = zf.read(info.filename)
                        depth = _max_zip_depth(nested_bytes, current_depth + 1, limit)
                        if depth > max_depth:
                            max_depth = depth
                        if max_depth > limit:
                            return max_depth
                    except Exception:  # noqa: BLE001
                        pass
            return max_depth
    except Exception:  # noqa: BLE001
        return current_depth


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

        # 6. Archive bomb: ZIP nesting depth exceeds configured limit
        if identity.mime_detected == "application/zip" or path.suffix.lower() == ".zip":
            try:
                raw = path.read_bytes()
                depth = _max_zip_depth(raw, current_depth=1, limit=settings.max_archive_depth)
                if depth > settings.max_archive_depth:
                    hits.append(RuleHit(
                        scanner="ANOMALY",
                        rule_id="ARCHIVE_BOMB",
                        severity="HIGH",
                        match_snippet=(
                            f"ZIP nesting depth={depth} exceeds limit={settings.max_archive_depth}"
                        ),
                    ))
            except Exception:  # noqa: BLE001
                pass

        return hits
