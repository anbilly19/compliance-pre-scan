"""FastAPI application exposing the compliance pre-scan endpoints."""
from __future__ import annotations

import io
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse

from ..audit.db import init_db, list_events, write_event
from ..audit.export import generate_csv
from ..audit.models import Decision, ScanResult
from ..pipeline import run_scan


SUPPORTED_EXTENSIONS = {".pdf", ".docx", ".doc", ".xlsx", ".xlsm", ".txt", ".rtf", ".zip"}
HTTP_BLOCKED = 451


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield


app = FastAPI(
    title="Compliance Pre-Scan",
    version="0.1.0",
    description="Local pre-upload content security scanner.",
    lifespan=lifespan,
)


@app.post("/scan")
async def scan_file(
    file: UploadFile = File(...),
    user_id: str = Form(...),
    session_id: str = Form(default=""),
):
    """
    Pre-upload compliance scan.

    Returns
    -------
    200  ScanResult JSON   decision == ALLOW or ALLOW_WITH_WARNING
    451  ScanResult JSON   decision == BLOCK  (file must not be forwarded to LLM)
    415  error JSON        unsupported file type
    """
    filename = file.filename or "unknown"
    ext = Path(filename).suffix.lower()

    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported file type '{ext}'. Supported: {sorted(SUPPORTED_EXTENSIONS)}",
        )

    content = await file.read()

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)

    try:
        result: ScanResult = run_scan(tmp_path, filename=filename)
    finally:
        tmp_path.unlink(missing_ok=True)

    await write_event(
        upload_id=result.upload_id,
        user_id=user_id,
        session_id=session_id,
        filename=filename,
        result=result,
    )

    result_dict = result.model_dump(mode="json")

    if result.decision == Decision.BLOCK:
        return JSONResponse(status_code=HTTP_BLOCKED, content=result_dict)

    return JSONResponse(status_code=200, content=result_dict)


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
        io.BytesIO(csv_content.encode("utf-8-sig")),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="compliance_export.csv"'},
    )
