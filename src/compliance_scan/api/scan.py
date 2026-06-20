"""POST /scan endpoint — pre-upload compliance scan."""
import tempfile
import time
import uuid
from pathlib import Path

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from ..audit.db import write_event
from ..audit.models import Decision, ScanResult
from ..pipeline import run_scan

router = APIRouter(tags=["scan"])

SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".xlsx", ".txt", ".rtf"}

# HTTP 451 = "Unavailable For Legal Reasons" — used here to signal a compliance BLOCK.
# The response body is always a full ScanResult JSON so the caller can log/display details.
HTTP_BLOCKED = 451


@router.post("/scan")
async def scan_file(
    file: UploadFile = File(...),
    user_id: str = Form(...),
    session_id: str = Form(default=""),
):
    """
    Pre-upload compliance scan.

    Returns
    -------
    200  ScanResult   decision == ALLOW or ALLOW_WITH_WARNING
    451  ScanResult   decision == BLOCK  (file must not be sent to LLM)
    415  error        unsupported file type
    """
    filename = file.filename or "unknown"
    ext = Path(filename).suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}",
        )

    data = await file.read()

    # Write to a temp file so the pipeline (which works with Path) can read it.
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(data)
        tmp_path = Path(tmp.name)

    try:
        result: ScanResult = run_scan(tmp_path, filename=filename)
    finally:
        tmp_path.unlink(missing_ok=True)

    # Persist audit event
    await write_event(
        upload_id=result.upload_id,
        user_id=user_id,
        session_id=session_id,
        filename=filename,
        result=result,
    )

    result_dict = result.model_dump(mode="json")

    if result.decision == Decision.BLOCK:
        # Return 451 so the upstream chat layer / SDK can detect and hard-block the upload.
        # The full ScanResult body lets the UI display exactly why it was blocked.
        return JSONResponse(status_code=HTTP_BLOCKED, content=result_dict)

    return JSONResponse(status_code=200, content=result_dict)
