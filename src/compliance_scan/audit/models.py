"""Pydantic models for scan results and audit events."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class RiskLevel(str, Enum):
    CLEAN = "CLEAN"
    SENSITIVE_PII = "SENSITIVE_PII"
    SECRET_FOUND = "SECRET_FOUND"
    STRUCTURAL_ANOMALY = "STRUCTURAL_ANOMALY"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    ALLOW_WITH_WARNING = "ALLOW_WITH_WARNING"
    BLOCK = "BLOCK"


class RuleHit(BaseModel):
    scanner: str                    # PII | SECRET | KEYWORD | ANOMALY
    rule_id: str
    entity_type: Optional[str] = None
    severity: str = "MEDIUM"        # LOW | MEDIUM | HIGH
    page_num: Optional[int] = None
    offset_char: Optional[int] = None
    match_snippet: str = ""         # masked, max 80 chars


class ScanResult(BaseModel):
    upload_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    file_type_detected: str
    file_type_declared: str
    extension_mismatch: bool = False
    risk_level: RiskLevel = RiskLevel.CLEAN
    decision: Decision = Decision.ALLOW
    pii_matches: list[RuleHit] = Field(default_factory=list)
    secret_matches: list[RuleHit] = Field(default_factory=list)
    keyword_matches: list[RuleHit] = Field(default_factory=list)
    anomaly_matches: list[RuleHit] = Field(default_factory=list)
    scan_duration_ms: int = 0


class AuditEvent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    user_id: str
    session_id: str = ""
    upload_id: str
    filename: str
    action: str = "PRE_SCAN_COMPLETED"
    risk_level: RiskLevel
    decision: Decision
    pii_count: int = 0
    secret_count: int = 0
    keyword_count: int = 0
    anomaly_flags: str = "[]"       # JSON-serialised list of rule_ids
    scan_duration_ms: int = 0
