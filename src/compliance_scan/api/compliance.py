"""Compliance event listing and Betriebsrat CSV export endpoints."""
from fastapi import APIRouter, Query
from fastapi.responses import StreamingResponse

from ..audit.db import list_events
from ..audit.export import generate_csv

router = APIRouter(prefix="/compliance", tags=["compliance"])


@router.get("/events")
async def get_events(
    user_id: str | None = Query(default=None),
    from_date: str | None = Query(default=None, description="ISO date YYYY-MM-DD"),
    to_date: str | None = Query(default=None, description="ISO date YYYY-MM-DD"),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0),
):
    """List compliance audit events with optional filters."""
    events = await list_events(
        user_id=user_id,
        from_date=from_date,
        to_date=to_date,
        limit=limit,
        offset=offset,
    )
    return {"total": len(events), "events": events}


@router.get("/export", response_class=StreamingResponse)
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
