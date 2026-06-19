"""POST /scan endpoint."""
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from ..extractors import get_extractor
from ..scanners.file_identity import check_file_identity
from ..audit.models import ScanResult, RuleHit, RiskLevel, Decision
from ..audit.db import write_event

router = APIRouter(tags=["scan"])

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".txt", ".rtf"}


@router.post("/scan", response_model=ScanResult)
async def scan_file(
    file: UploadFile = File(...),
    user_id: str = Form(...),
    session_id: str = Form(default=""),
):
    """
    Pre-upload compliance scan.
    Accepts a file upload, runs all detection layers,
    returns a ScanResult and writes an audit event.
    """
    t_start = time.monotonic()
    upload_id = str(uuid.uuid4())
    filename = file.filename or "unknown"
    ext = Path(filename).suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}",
        )

    data = await file.read()

    # --- 1. File identity check ---
    identity = check_file_identity(data, filename)

    # --- 2. Text extraction ---
    extractor = get_extractor(ext)
    if extractor is None:
        raise HTTPException(status_code=415, detail="No extractor available")
    extraction = extractor.extract(data, filename)

    # --- 3-6. Scanners (Phase 2 — stubs return empty lists for now) ---
    pii_matches: list[RuleHit] = []
    secret_matches: list[RuleHit] = []
    keyword_matches: list[RuleHit] = []
    anomaly_matches: list[RuleHit] = []

    # Structural anomaly from file identity
    if identity.extension_mismatch or identity.is_suspicious_type:
        anomaly_matches.append(RuleHit(
            scanner="ANOMALY",
            rule_id="FILE_IDENTITY_MISMATCH",
            entity_type="extension_mismatch" if identity.extension_mismatch else "suspicious_type",
            severity="HIGH",
            match_snippet=identity.note[:80],
        ))

    # --- 7. Policy decision (Phase 3 — simple inline rules for now) ---
    from ..policy.engine import evaluate
    risk_level, decision = evaluate(
        pii_matches=pii_matches,
        secret_matches=secret_matches,
        anomaly_matches=anomaly_matches,
        keyword_matches=keyword_matches,
    )

    scan_duration_ms = int((time.monotonic() - t_start) * 1000)

    result = ScanResult(
        upload_id=upload_id,
        filename=filename,
        file_type_detected=identity.detected_mime,
        file_type_declared=identity.declared_mime,
        extension_mismatch=identity.extension_mismatch,
        risk_level=risk_level,
        decision=decision,
        pii_matches=pii_matches,
        secret_matches=secret_matches,
        keyword_matches=keyword_matches,
        anomaly_matches=anomaly_matches,
        scan_duration_ms=scan_duration_ms,
    )

    # --- 8. Write audit event ---
    await write_event(
        upload_id=upload_id,
        user_id=user_id,
        session_id=session_id,
        filename=filename,
        result=result,
    )

    return result
