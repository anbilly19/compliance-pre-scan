"""SQLite schema initialisation and async read/write helpers."""
import json
import uuid
from pathlib import Path

import aiosqlite

from ..config import settings
from .models import AuditEvent, ScanResult, RiskLevel, Decision

DDL = """
CREATE TABLE IF NOT EXISTS compliance_events (
    id               TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    session_id       TEXT,
    upload_id        TEXT NOT NULL,
    filename         TEXT NOT NULL,
    action           TEXT NOT NULL,
    risk_level       TEXT NOT NULL,
    decision         TEXT NOT NULL,
    pii_count        INTEGER DEFAULT 0,
    secret_count     INTEGER DEFAULT 0,
    keyword_count    INTEGER DEFAULT 0,
    anomaly_flags    TEXT    DEFAULT '[]',
    scan_duration_ms INTEGER,
    breach_reason    TEXT,
    breach_severity  TEXT,
    breach_reporter  TEXT
);

CREATE TABLE IF NOT EXISTS compliance_rule_hits (
    id          TEXT PRIMARY KEY,
    event_id    TEXT NOT NULL REFERENCES compliance_events(id),
    scanner     TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    entity_type TEXT,
    severity    TEXT NOT NULL,
    page_num    INTEGER,
    offset_char INTEGER,
    snippet     TEXT
);

CREATE INDEX IF NOT EXISTS idx_events_user   ON compliance_events(user_id);
CREATE INDEX IF NOT EXISTS idx_events_ts     ON compliance_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_action ON compliance_events(action);
CREATE INDEX IF NOT EXISTS idx_hits_event    ON compliance_rule_hits(event_id);
"""


async def init_db() -> None:
    """Create tables if they don't exist yet."""
    settings.db_path.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(settings.db_path) as db:
        await db.executescript(DDL)
        # Add new columns to existing DBs (safe: fails silently if already present)
        for col_sql in [
            "ALTER TABLE compliance_events ADD COLUMN breach_reason   TEXT",
            "ALTER TABLE compliance_events ADD COLUMN breach_severity  TEXT",
            "ALTER TABLE compliance_events ADD COLUMN breach_reporter  TEXT",
        ]:
            try:
                await db.execute(col_sql)
            except Exception:
                pass
        await db.commit()


async def write_event(
    upload_id: str,
    user_id: str,
    session_id: str,
    filename: str,
    result: ScanResult,
) -> AuditEvent:
    """Persist one scan result as an audit event + individual rule hits."""
    anomaly_flag_ids = [h.rule_id for h in result.anomaly_matches]

    event = AuditEvent(
        user_id=user_id,
        session_id=session_id,
        upload_id=upload_id,
        filename=filename,
        risk_level=result.risk_level,
        decision=result.decision,
        pii_count=len(result.pii_matches),
        secret_count=len(result.secret_matches),
        keyword_count=len(result.keyword_matches),
        anomaly_flags=json.dumps(anomaly_flag_ids),
        scan_duration_ms=result.scan_duration_ms,
    )

    all_hits = (
        result.pii_matches
        + result.secret_matches
        + result.keyword_matches
        + result.anomaly_matches
    )

    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """
            INSERT INTO compliance_events
              (id, timestamp, user_id, session_id, upload_id, filename,
               action, risk_level, decision, pii_count, secret_count,
               keyword_count, anomaly_flags, scan_duration_ms)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event.id, event.timestamp, event.user_id, event.session_id,
                event.upload_id, event.filename, event.action,
                event.risk_level.value, event.decision.value,
                event.pii_count, event.secret_count, event.keyword_count,
                event.anomaly_flags, event.scan_duration_ms,
            ),
        )

        for hit in all_hits:
            await db.execute(
                """
                INSERT INTO compliance_rule_hits
                  (id, event_id, scanner, rule_id, entity_type,
                   severity, page_num, offset_char, snippet)
                VALUES (?,?,?,?,?,?,?,?,?)
                """,
                (
                    str(uuid.uuid4()), event.id,
                    hit.scanner, hit.rule_id, hit.entity_type,
                    hit.severity, hit.page_num, hit.offset_char,
                    hit.match_snippet[:80] if hit.match_snippet else None,
                ),
            )

        await db.commit()

    return event


async def write_breach_report(
    user_id: str,
    session_id: str,
    upload_id: str,
    filename: str,
    reason: str,
    severity: str,
    reporter: str,
) -> dict:
    """Write a manual MANUAL_BREACH_REPORT event to the audit trail."""
    from datetime import datetime, timezone

    event_id = str(uuid.uuid4())
    timestamp = datetime.now(timezone.utc).isoformat()

    async with aiosqlite.connect(settings.db_path) as db:
        await db.execute(
            """
            INSERT INTO compliance_events
              (id, timestamp, user_id, session_id, upload_id, filename,
               action, risk_level, decision,
               pii_count, secret_count, keyword_count, anomaly_flags,
               scan_duration_ms, breach_reason, breach_severity, breach_reporter)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                event_id, timestamp, user_id, session_id,
                upload_id, filename,
                "MANUAL_BREACH_REPORT", "SENSITIVE_PII", "BLOCK",
                0, 0, 0, "[]", 0,
                reason, severity, reporter,
            ),
        )
        await db.commit()

    return {
        "id": event_id,
        "timestamp": timestamp,
        "action": "MANUAL_BREACH_REPORT",
        "severity": severity,
        "reporter": reporter,
        "upload_id": upload_id,
        "filename": filename,
    }


async def list_events(
    user_id: str | None = None,
    from_date: str | None = None,
    to_date: str | None = None,
    action: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict]:
    """Query compliance events with optional filters."""
    clauses: list[str] = []
    params: list = []

    if user_id:
        clauses.append("user_id = ?")
        params.append(user_id)
    if from_date:
        clauses.append("timestamp >= ?")
        params.append(from_date)
    if to_date:
        clauses.append("timestamp <= ?")
        params.append(to_date + "T23:59:59")
    if action:
        clauses.append("action = ?")
        params.append(action)

    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    sql = f"""
        SELECT id, timestamp, user_id, session_id, upload_id, filename,
               action, risk_level, decision, pii_count, secret_count,
               keyword_count, anomaly_flags, scan_duration_ms,
               breach_reason, breach_severity, breach_reporter
        FROM compliance_events
        {where}
        ORDER BY timestamp DESC
        LIMIT ? OFFSET ?
    """
    params += [limit, offset]

    async with aiosqlite.connect(settings.db_path) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, params) as cursor:
            rows = await cursor.fetchall()

    return [dict(r) for r in rows]
