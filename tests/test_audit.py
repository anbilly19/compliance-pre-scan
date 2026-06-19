"""Tests for the audit DB layer."""
import pytest
from pathlib import Path
from compliance_scan.audit.models import ScanResult, RiskLevel, Decision
from compliance_scan.audit import db as audit_db


@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    """Redirect DB to a temp path for isolation."""
    db_file = tmp_path / "test.db"
    monkeypatch.setattr(audit_db.settings, "db_path", db_file)
    return db_file


@pytest.mark.asyncio
async def test_init_and_write(tmp_db):
    await audit_db.init_db()

    result = ScanResult(
        filename="test.txt",
        file_type_detected="text/plain",
        file_type_declared="text/plain",
        risk_level=RiskLevel.CLEAN,
        decision=Decision.ALLOW,
    )
    event = await audit_db.write_event(
        upload_id=result.upload_id,
        user_id="user-001",
        session_id="sess-abc",
        filename="test.txt",
        result=result,
    )
    assert event.user_id == "user-001"

    events = await audit_db.list_events(user_id="user-001")
    assert len(events) == 1
    assert events[0]["filename"] == "test.txt"


@pytest.mark.asyncio
async def test_filter_by_date(tmp_db):
    await audit_db.init_db()
    result = ScanResult(
        filename="doc.pdf",
        file_type_detected="application/pdf",
        file_type_declared="application/pdf",
        risk_level=RiskLevel.SENSITIVE_PII,
        decision=Decision.ALLOW_WITH_WARNING,
    )
    await audit_db.write_event(
        upload_id=result.upload_id,
        user_id="user-002",
        session_id="",
        filename="doc.pdf",
        result=result,
    )
    events = await audit_db.list_events(from_date="2000-01-01", to_date="2099-12-31")
    assert any(e["filename"] == "doc.pdf" for e in events)
