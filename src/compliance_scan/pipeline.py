"""Main orchestrator: runs all scanners in sequence and produces a ScanResult."""
from __future__ import annotations

import logging
import time
from pathlib import Path

from .audit.models import RuleHit, RiskLevel, Decision, ScanResult
from .config import settings
from .extractors import extract_text
from .masking import mask_result
from .policy.engine import PolicyInput, evaluate
from .scanners import (
    identify_file,
    PIIScanner,
    SecretScanner,
    KeywordScanner,
    AnomalyScanner,
)

log = logging.getLogger(__name__)

_pii     = PIIScanner()
_secret  = SecretScanner()
_keyword = KeywordScanner(config_paths=settings.keyword_config_paths)
_anomaly = AnomalyScanner()


def run_scan(path: Path, filename: str | None = None) -> ScanResult:
    """
    Full pre-upload scan pipeline.
    1.  Identify file type
    2.  Extract text
    3.  Run PII / secret / keyword / anomaly scanners
    4.  Evaluate policy (OPA or inline fallback)
    5.  Apply hit masking when mask_snippets=True
    """
    t0 = time.monotonic()
    fname = filename or path.name
    log.info(
        "run_scan START file=%r mask=%s opa=%s",
        fname, settings.mask_snippets, bool(settings.opa_url),
    )

    # Step 1
    identity = identify_file(path)
    log.debug(
        "file_identity mime_detected=%s mime_ext=%s mismatch=%s",
        identity.mime_detected, identity.mime_from_extension, identity.extension_mismatch,
    )

    # Step 2
    extraction = extract_text(
        path,
        mime_type=identity.mime_detected
        if identity.mime_detected != "application/octet-stream"
        else None,
    )
    log.debug("extraction chars=%d", len(extraction.text))

    # Step 3
    pii_hits     = _pii.scan(extraction.text)
    secret_hits  = _secret.scan(extraction.text)
    keyword_hits = _keyword.scan(extraction.text)
    anomaly_hits = _anomaly.scan(path, identity, extraction)

    log.info(
        "scan hits — pii=%d secrets=%d keywords=%d anomalies=%d",
        len(pii_hits), len(secret_hits), len(keyword_hits), len(anomaly_hits),
    )

    # Step 4 — policy
    high_anomalies = [h for h in anomaly_hits if h.severity == "HIGH"]
    policy_inp = PolicyInput(
        pii_count=len(pii_hits),
        secret_count=len(secret_hits),
        keyword_count=len(keyword_hits),
        high_anomaly_count=len(high_anomalies),
    )
    policy_result = evaluate(policy_inp)
    log.info(
        "policy decision risk=%s decision=%s reason=%s backend=%s",
        policy_result.risk_level, policy_result.decision,
        policy_result.reason, "opa" if settings.opa_url else "inline",
    )

    result = ScanResult(
        filename=fname,
        file_type_detected=identity.mime_detected,
        file_type_declared=identity.mime_from_extension,
        extension_mismatch=identity.extension_mismatch,
        risk_level=policy_result.risk_level,
        decision=policy_result.decision,
        pii_matches=pii_hits,
        secret_matches=secret_hits,
        keyword_matches=keyword_hits,
        anomaly_matches=anomaly_hits,
    )
    result.scan_duration_ms = int((time.monotonic() - t0) * 1000)

    # Step 5 — masking
    result = mask_result(result)

    log.info(
        "run_scan END file=%r risk=%s decision=%s duration_ms=%d",
        fname, result.risk_level, result.decision, result.scan_duration_ms,
    )
    return result
