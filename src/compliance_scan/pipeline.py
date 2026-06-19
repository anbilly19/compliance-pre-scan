"""Main orchestrator: runs all scanners in sequence and produces a ScanResult."""
from __future__ import annotations

import time
from pathlib import Path

from .audit.models import RuleHit, RiskLevel, Decision, ScanResult
from .config import settings
from .extractors import extract_text
from .scanners import (
    identify_file,
    PIIScanner,
    SecretScanner,
    KeywordScanner,
    AnomalyScanner,
)

# Module-level scanner singletons (initialised once per process)
_pii = PIIScanner()
_secret = SecretScanner()
_keyword = KeywordScanner(config_paths=settings.keyword_config_paths)
_anomaly = AnomalyScanner()


def run_scan(path: Path, filename: str | None = None) -> ScanResult:
    """
    Full pre-upload scan pipeline.

    1. Identify file type
    2. Extract text
    3. Run PII / secret / keyword / anomaly scanners
    4. Derive risk level and decision
    """
    t0 = time.monotonic()
    fname = filename or path.name

    # Step 1: file identity
    identity = identify_file(path)

    # Step 2: text extraction
    extraction = extract_text(
        path,
        mime_type=identity.mime_detected
        if identity.mime_detected != "application/octet-stream"
        else None,
    )

    # Step 3: scanners
    pii_hits: list[RuleHit] = _pii.scan(extraction.text)
    secret_hits: list[RuleHit] = _secret.scan(extraction.text)
    keyword_hits: list[RuleHit] = _keyword.scan(extraction.text)
    anomaly_hits: list[RuleHit] = _anomaly.scan(path, identity, extraction)

    # Step 4: policy
    result = _derive_decision(
        filename=fname,
        identity=identity,
        pii_hits=pii_hits,
        secret_hits=secret_hits,
        keyword_hits=keyword_hits,
        anomaly_hits=anomaly_hits,
    )
    result.scan_duration_ms = int((time.monotonic() - t0) * 1000)
    return result


def _derive_decision(
    filename: str,
    identity,
    pii_hits: list[RuleHit],
    secret_hits: list[RuleHit],
    keyword_hits: list[RuleHit],
    anomaly_hits: list[RuleHit],
) -> ScanResult:
    """Translate scanner output into a risk level and decision."""
    risk = RiskLevel.CLEAN
    decision = Decision.ALLOW

    high_anomalies = [h for h in anomaly_hits if h.severity == "HIGH"]

    if len(secret_hits) >= settings.secret_warn_threshold:
        risk = RiskLevel.SECRET_FOUND
        decision = Decision.ALLOW_WITH_WARNING

    if len(pii_hits) >= settings.pii_warn_threshold:
        # Escalate risk; decision stays ALLOW_WITH_WARNING (warn-only mode)
        if risk == RiskLevel.CLEAN:
            risk = RiskLevel.SENSITIVE_PII
        decision = Decision.ALLOW_WITH_WARNING

    if keyword_hits and decision == Decision.ALLOW:
        risk = RiskLevel.SENSITIVE_PII
        decision = Decision.ALLOW_WITH_WARNING

    if high_anomalies:
        risk = RiskLevel.STRUCTURAL_ANOMALY
        decision = Decision.ALLOW_WITH_WARNING

    return ScanResult(
        filename=filename,
        file_type_detected=identity.mime_detected,
        file_type_declared=identity.mime_from_extension,
        extension_mismatch=identity.extension_mismatch,
        risk_level=risk,
        decision=decision,
        pii_matches=pii_hits,
        secret_matches=secret_hits,
        keyword_matches=keyword_hits,
        anomaly_matches=anomaly_hits,
    )
