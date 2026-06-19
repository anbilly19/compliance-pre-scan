"""Integration tests for the FastAPI endpoints."""
import pytest
from httpx import ASGITransport, AsyncClient
from pathlib import Path

from compliance_scan.api.app import app
from compliance_scan.audit import db as audit_db


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(audit_db.settings, "db_path", tmp_path / "test.db")


@pytest.mark.asyncio
async def test_scan_clean_txt(tmp_path):
    f = tmp_path / "clean.txt"
    f.write_text("Meeting notes: nothing sensitive here.", encoding="utf-8")

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await app.router.startup()
        resp = await client.post(
            "/scan",
            data={"user_id": "user-001", "session_id": "s1"},
            files={"file": ("clean.txt", f.read_bytes(), "text/plain")},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] in ("ALLOW", "ALLOW_WITH_WARNING")


@pytest.mark.asyncio
async def test_scan_with_secret(tmp_path):
    f = tmp_path / "secrets.txt"
    f.write_text(
        "Config: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE secretsabound",
        encoding="utf-8",
    )

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await app.router.startup()
        resp = await client.post(
            "/scan",
            data={"user_id": "user-001", "session_id": "s1"},
            files={"file": ("secrets.txt", f.read_bytes(), "text/plain")},
        )

    assert resp.status_code == 200
    body = resp.json()
    assert body["decision"] == "ALLOW_WITH_WARNING"
    assert len(body["secret_matches"]) > 0


@pytest.mark.asyncio
async def test_export_csv():
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as client:
        await app.router.startup()
        resp = await client.get("/events/export")

    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
