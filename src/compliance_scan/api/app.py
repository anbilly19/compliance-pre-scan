"""FastAPI application exposing the compliance pre-scan endpoints."""
from __future__ import annotations

import io
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import StreamingResponse

from ..audit.db import init_db, list_events, write_event
from ..audit.export import generate_csv
from ..audit.models import ScanResult
from ..pipeline import run_scan

app = FastAPI(
    title="Compliance Pre-Scan",
    version="0.1.0",
    description="Local pre-upload content security scanner.",
)


@app.on_event("startup")
async def startup() -> None:
    await init_db()


@app.post("/scan", response_model=ScanResult)
async def scan_file(
    file: UploadFile = File(...),
    user_id: str = Form(...),
    session_id: str = Form(default=""),
) -> ScanResult:
    """
    Accepts a file upload, runs the full compliance scan pipeline, writes an
    audit event, and returns the ScanResult.

    The caller should:
      - Allow the upload to proceed if decision == ALLOW.
      - Show a warning banner if decision == ALLOW_WITH_WARNING.
      - Block the upload if decision == BLOCK (future policy upgrade path).
    """
    content = await file.read()
    filename = file.filename or "unknown"

    # Write to a temp file so scanners can read by Path
    suffix = Path(filename).suffix or ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        result = run_scan(tmp_path, filename=filename)
    finally:
        tmp_path.unlink(missing_ok=True)

    await write_event(
        upload_id=result.upload_id,
        user_id=user_id,
        session_id=session_id,
        filename=filename,
        result=result,
    )

    return result


@app.get("/events")
async def get_events(
    user_id: Optional[str] = Query(default=None),
    from_date: Optional[str] = Query(default=None, description="ISO date: YYYY-MM-DD"),
    to_date: Optional[str] = Query(default=None, description="ISO date: YYYY-MM-DD"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0),
) -> list[dict]:
    """Query the audit trail with optional filters."""
    return await list_events(
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
        limit=limit,
        offset=offset,
    )


@app.get("/events/export")
async def export_events(
    user_id: Optional[str] = Query(default=None),
    from_date: Optional[str] = Query(default=None),
    to_date: Optional[str] = Query(default=None),
) -> StreamingResponse:
    """Download compliance events as a CSV (Betriebsrat / audit export)."""
    events = await list_events(
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
        limit=10_000,
    )
    csv_content = generate_csv(events)
    return StreamingResponse(
        io.BytesIO(csv_content.encode("utf-8-sig")),  # BOM for Excel compat
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="compliance_export.csv"'},
    )
