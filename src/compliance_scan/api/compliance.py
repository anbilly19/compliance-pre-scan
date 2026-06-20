"""Compliance event listing, breach reports, and Betriebsrat CSV export endpoints."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Body, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from ..audit.db import list_events, write_breach_report
from ..audit.export import generate_csv

router = APIRouter(prefix="/compliance", tags=["compliance"])


# ── GET /compliance/events ────────────────────────────────────────────────────
@router.get("/events")
async def get_events(
    user_id: str | None = Query(default=None),
    from_date: str | None = Query(default=None, description="ISO date YYYY-MM-DD"),
    to_date: str | None = Query(default=None, description="ISO date YYYY-MM-DD"),
    action: str | None = Query(default=None, description="Filter by action type, e.g. MANUAL_BREACH_REPORT"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0),
):
    """List compliance audit events with optional filters."""
    events = await list_events(
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
        action=action,
        limit=limit,
        offset=offset,
    )
    return {"total": len(events), "events": events}


# ── GET /compliance/events/export ─────────────────────────────────────────────
@router.get("/events/export", response_class=StreamingResponse)
async def export_csv(
    from_date: str | None = Query(default=None),
    to_date: str | None = Query(default=None),
    user_id: str | None = Query(default=None),
):
    """Download compliance events as CSV (Betriebsrat export)."""
    events = await list_events(
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
        limit=10_000,
        offset=0,
    )
    csv_content = generate_csv(events)
    return StreamingResponse(
        iter([csv_content]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=compliance_export.csv"},
    )


# ── POST /compliance/breach-report ────────────────────────────────────────────
class BreachReportRequest(BaseModel):
    user_id: str
    session_id: str = ""
    upload_id: str = ""
    filename: str = "(not linked to upload)"
    reason: str
    severity: str = "MEDIUM"   # LOW | MEDIUM | HIGH | CRITICAL
    reporter: str = ""


@router.post("/breach-report", status_code=201)
async def submit_breach_report(body: BreachReportRequest):
    """Submit a manual data breach / compliance concern report.

    Creates a MANUAL_BREACH_REPORT event in the audit trail.
    Intended for the 'Datenpanne melden' button in the platform UI.
    """
    event = await write_breach_report(
        user_id=body.user_id,
        session_id=body.session_id,
        upload_id=body.upload_id or str(uuid.uuid4()),
        filename=body.filename,
        reason=body.reason,
        severity=body.severity,
        reporter=body.reporter or body.user_id,
    )
    return {"status": "recorded", "event": event}
