"""CSV export for Betriebsrat / audit purposes."""
import csv
import hashlib
import io
import json

from ..config import settings


def _pseudonymise(user_id: str) -> str:
    return hashlib.sha256(user_id.encode()).hexdigest()[:16]


def generate_csv(events: list[dict]) -> str:
    """
    Serialise audit events to a CSV string.
    User IDs are pseudonymised when settings.export_pseudonymise_users is True.
    Raw file content is never included.
    """
    buf = io.StringIO()
    fieldnames = [
        "timestamp",
        "user_id",
        "session_id",
        "upload_id",
        "filename",
        "risk_level",
        "decision",
        "pii_count",
        "secret_count",
        "keyword_count",
        "anomaly_flags",
        "scan_duration_ms",
    ]
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()

    for ev in events:
        row = dict(ev)
        if settings.export_pseudonymise_users:
            row["user_id"] = _pseudonymise(row.get("user_id", ""))
        # flatten anomaly_flags JSON to a readable string
        try:
            flags = json.loads(row.get("anomaly_flags", "[]"))
            row["anomaly_flags"] = "; ".join(flags) if flags else ""
        except (json.JSONDecodeError, TypeError):
            pass
        writer.writerow(row)

    return buf.getvalue()
