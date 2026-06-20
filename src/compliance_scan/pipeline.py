"""Main orchestrator: runs all scanners in sequence and produces a ScanResult."""
from __future__ import annotations

import logging
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

log = logging.getLogger(__name__)

# Module-level scanner singletons (loaded once at startup)
_pii     = PIIScanner()
_secret  = SecretScanner()
_keyword = KeywordScanner(config_paths=settings.keyword_config_paths)
_anomaly = AnomalyScanner()


def run_scan(path: Path, filename: str | None = None) -> ScanResult:
    """
    Full pre-upload scan pipeline.
    1. Identify file type
    2. Extract text
    3. Run PII / secret / keyword / anomaly scanners
    4. Derive risk level and decision (including BLOCK when thresholds exceeded)
    """
    t0 = time.monotonic()
    fname = filename or path.name
    log.info("run_scan START file=%r", fname)

    # Step 1 — file identity
    identity = identify_file(path)
    log.debug(
        "file_identity mime_detected=%s mime_ext=%s mismatch=%s",
        identity.mime_detected, identity.mime_from_extension, identity.extension_mismatch,
    )

    # Step 2 — text extraction
    extraction = extract_text(
        path,
        mime_type=identity.mime_detected
        if identity.mime_detected != "application/octet-stream"
        else None,
    )
    log.debug("extraction chars=%d pages=%s", len(extraction.text), getattr(extraction, "page_count", "?"))

    # Step 3 — scanners
    pii_hits     = _pii.scan(extraction.text)
    secret_hits  = _secret.scan(extraction.text)
    keyword_hits = _keyword.scan(extraction.text)
    anomaly_hits = _anomaly.scan(path, identity, extraction)

    log.info(
        "scan hits — pii=%d secrets=%d keywords=%d anomalies=%d",
        len(pii_hits), len(secret_hits), len(keyword_hits), len(anomaly_hits),
    )

    # Step 4 — policy decision
    result = _derive_decision(
        filename=fname,
        identity=identity,
        pii_hits=pii_hits,
        secret_hits=secret_hits,
        keyword_hits=keyword_hits,
        anomaly_hits=anomaly_hits,
    )
    result.scan_duration_ms = int((time.monotonic() - t0) * 1000)

    log.info(
        "run_scan END file=%r risk=%s decision=%s duration_ms=%d",
        fname, result.risk_level, result.decision, result.scan_duration_ms,
    )
    return result


def _derive_decision(
    filename: str,
    identity,
    pii_hits: list[RuleHit],
    secret_hits: list[RuleHit],
    keyword_hits: list[RuleHit],
    anomaly_hits: list[RuleHit],
) -> ScanResult:
    """Map scan hits to a RiskLevel + Decision according to configured thresholds.

    Decision priority (highest wins):
        BLOCK > ALLOW_WITH_WARNING > ALLOW
    """
    risk     = RiskLevel.CLEAN
    decision = Decision.ALLOW

    high_anomalies = [h for h in anomaly_hits if h.severity == "HIGH"]

    # ── Secrets ───────────────────────────────────────────────────────────────
    if len(secret_hits) >= settings.secret_warn_threshold:
        risk     = RiskLevel.SECRET_FOUND
        decision = Decision.ALLOW_WITH_WARNING
        log.warning("Policy: SECRET_FOUND (%d hits) warn_threshold=%d", len(secret_hits), settings.secret_warn_threshold)

    if settings.block_on_secret > 0 and len(secret_hits) >= settings.block_on_secret:
        risk     = RiskLevel.SECRET_FOUND
        decision = Decision.BLOCK
        log.warning("Policy: BLOCK on secret (%d hits) block_threshold=%d", len(secret_hits), settings.block_on_secret)

    # ── PII ───────────────────────────────────────────────────────────────────
    if len(pii_hits) >= settings.pii_warn_threshold:
        if risk == RiskLevel.CLEAN:
            risk = RiskLevel.SENSITIVE_PII
        if decision == Decision.ALLOW:
            decision = Decision.ALLOW_WITH_WARNING
        log.warning("Policy: SENSITIVE_PII (%d hits) warn_threshold=%d", len(pii_hits), settings.pii_warn_threshold)

    if settings.block_on_pii > 0 and len(pii_hits) >= settings.block_on_pii:
        risk     = RiskLevel.SENSITIVE_PII
        decision = Decision.BLOCK
        log.warning("Policy: BLOCK on PII (%d hits) block_threshold=%d", len(pii_hits), settings.block_on_pii)

    # ── Keywords ──────────────────────────────────────────────────────────────
    if keyword_hits and decision == Decision.ALLOW:
        risk     = RiskLevel.SENSITIVE_PII
        decision = Decision.ALLOW_WITH_WARNING
        log.warning("Policy: KEYWORD match (%d hits)", len(keyword_hits))

    # ── Structural anomalies ──────────────────────────────────────────────────
    if high_anomalies:
        if decision != Decision.BLOCK:          # don't downgrade an existing BLOCK
            risk     = RiskLevel.STRUCTURAL_ANOMALY
            decision = Decision.ALLOW_WITH_WARNING
        log.warning("Policy: STRUCTURAL_ANOMALY (%d high hits)", len(high_anomalies))

    if settings.block_on_structural_anomaly and high_anomalies:
        risk     = RiskLevel.STRUCTURAL_ANOMALY
        decision = Decision.BLOCK
        log.warning("Policy: BLOCK on structural anomaly (%d high hits)", len(high_anomalies))

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
