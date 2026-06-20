"""Phase 10 — tests for BLOCK decision enforcement.

Covers:
- pipeline._derive_decision() returns BLOCK for secrets when block_on_secret > 0
- pipeline._derive_decision() returns BLOCK for structural anomalies when block_on_structural_anomaly=True
- pipeline._derive_decision() returns ALLOW_WITH_WARNING (not BLOCK) when block thresholds are at 0/False
- POST /scan returns HTTP 451 when decision == BLOCK
- POST /scan returns HTTP 200 when decision is ALLOW or ALLOW_WITH_WARNING
"""
import io
import types
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from compliance_scan.api.app import app
from compliance_scan.audit.models import RiskLevel, Decision, RuleHit, ScanResult
from compliance_scan.pipeline import _derive_decision


# ─── helpers ──────────────────────────────────────────────────────────────────

def _make_identity(mismatch: bool = False):
    identity = MagicMock()
    identity.mime_detected = "application/pdf"
    identity.mime_from_extension = "application/pdf"
    identity.extension_mismatch = mismatch
    return identity


def _secret_hit() -> RuleHit:
    return RuleHit(scanner="SECRET", rule_id="AWS_ACCESS_KEY", severity="HIGH", match_snippet="AKIA...")


def _high_anomaly_hit() -> RuleHit:
    return RuleHit(scanner="ANOMALY", rule_id="FILE_IDENTITY_MISMATCH", severity="HIGH", match_snippet="ext mismatch")


def _pii_hit() -> RuleHit:
    return RuleHit(scanner="PII", rule_id="EMAIL_ADDRESS", severity="HIGH", match_snippet="u@e.de")


# ─── unit tests: _derive_decision ─────────────────────────────────────────────

class TestDeriveDecisionBlock:

    def test_secret_triggers_block_when_threshold_1(self):
        with patch("compliance_scan.pipeline.settings") as s:
            s.secret_warn_threshold = 1
            s.block_on_secret = 1
            s.pii_warn_threshold = 1
            s.block_on_pii = 0
            s.block_on_structural_anomaly = False

            result = _derive_decision(
                filename="test.txt",
                identity=_make_identity(),
                pii_hits=[],
                secret_hits=[_secret_hit()],
                keyword_hits=[],
                anomaly_hits=[],
            )
        assert result.decision == Decision.BLOCK
        assert result.risk_level == RiskLevel.SECRET_FOUND

    def test_no_block_when_block_on_secret_zero(self):
        with patch("compliance_scan.pipeline.settings") as s:
            s.secret_warn_threshold = 1
            s.block_on_secret = 0
            s.pii_warn_threshold = 1
            s.block_on_pii = 0
            s.block_on_structural_anomaly = False

            result = _derive_decision(
                filename="test.txt",
                identity=_make_identity(),
                pii_hits=[],
                secret_hits=[_secret_hit()],
                keyword_hits=[],
                anomaly_hits=[],
            )
        assert result.decision == Decision.ALLOW_WITH_WARNING

    def test_structural_anomaly_blocks_when_enabled(self):
        with patch("compliance_scan.pipeline.settings") as s:
            s.secret_warn_threshold = 1
            s.block_on_secret = 1
            s.pii_warn_threshold = 1
            s.block_on_pii = 0
            s.block_on_structural_anomaly = True

            result = _derive_decision(
                filename="evil.exe",
                identity=_make_identity(mismatch=True),
                pii_hits=[],
                secret_hits=[],
                keyword_hits=[],
                anomaly_hits=[_high_anomaly_hit()],
            )
        assert result.decision == Decision.BLOCK
        assert result.risk_level == RiskLevel.STRUCTURAL_ANOMALY

    def test_structural_anomaly_warns_only_when_disabled(self):
        with patch("compliance_scan.pipeline.settings") as s:
            s.secret_warn_threshold = 1
            s.block_on_secret = 0
            s.pii_warn_threshold = 1
            s.block_on_pii = 0
            s.block_on_structural_anomaly = False

            result = _derive_decision(
                filename="suspicious.pdf",
                identity=_make_identity(),
                pii_hits=[],
                secret_hits=[],
                keyword_hits=[],
                anomaly_hits=[_high_anomaly_hit()],
            )
        assert result.decision == Decision.ALLOW_WITH_WARNING

    def test_pii_block_threshold_respected(self):
        pii_hits = [_pii_hit() for _ in range(5)]
        with patch("compliance_scan.pipeline.settings") as s:
            s.secret_warn_threshold = 1
            s.block_on_secret = 1
            s.pii_warn_threshold = 1
            s.block_on_pii = 5
            s.block_on_structural_anomaly = False

            result = _derive_decision(
                filename="personal.pdf",
                identity=_make_identity(),
                pii_hits=pii_hits,
                secret_hits=[],
                keyword_hits=[],
                anomaly_hits=[],
            )
        assert result.decision == Decision.BLOCK

    def test_clean_file_allowed(self):
        with patch("compliance_scan.pipeline.settings") as s:
            s.secret_warn_threshold = 1
            s.block_on_secret = 1
            s.pii_warn_threshold = 1
            s.block_on_pii = 0
            s.block_on_structural_anomaly = True

            result = _derive_decision(
                filename="clean.txt",
                identity=_make_identity(),
                pii_hits=[],
                secret_hits=[],
                keyword_hits=[],
                anomaly_hits=[],
            )
        assert result.decision == Decision.ALLOW
        assert result.risk_level == RiskLevel.CLEAN


# ─── integration tests: POST /scan HTTP status codes ─────────────────────────

client = TestClient(app, raise_server_exceptions=False)


def _upload(content: bytes, filename: str = "test.txt"):
    return client.post(
        "/scan",
        data={"user_id": "test-user", "session_id": "test-session"},
        files={"file": (filename, io.BytesIO(content), "text/plain")},
    )


class TestScanEndpointStatusCodes:

    def test_clean_file_returns_200(self):
        with patch("compliance_scan.api.scan.run_scan") as mock_scan, \
             patch("compliance_scan.api.scan.write_event"):
            mock_scan.return_value = ScanResult(
                filename="clean.txt",
                file_type_detected="text/plain",
                file_type_declared="text/plain",
                risk_level=RiskLevel.CLEAN,
                decision=Decision.ALLOW,
            )
            resp = _upload(b"hello world")
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW"

    def test_warn_file_returns_200(self):
        with patch("compliance_scan.api.scan.run_scan") as mock_scan, \
             patch("compliance_scan.api.scan.write_event"):
            mock_scan.return_value = ScanResult(
                filename="warn.txt",
                file_type_detected="text/plain",
                file_type_declared="text/plain",
                risk_level=RiskLevel.SENSITIVE_PII,
                decision=Decision.ALLOW_WITH_WARNING,
            )
            resp = _upload(b"Max Mustermann, mustermann@test.de")
        assert resp.status_code == 200
        assert resp.json()["decision"] == "ALLOW_WITH_WARNING"

    def test_blocked_file_returns_451(self):
        with patch("compliance_scan.api.scan.run_scan") as mock_scan, \
             patch("compliance_scan.api.scan.write_event"):
            mock_scan.return_value = ScanResult(
                filename="secrets.txt",
                file_type_detected="text/plain",
                file_type_declared="text/plain",
                risk_level=RiskLevel.SECRET_FOUND,
                decision=Decision.BLOCK,
                secret_matches=[_secret_hit()],
            )
            resp = _upload(b"AKIAIOSFODNN7EXAMPLE")
        assert resp.status_code == 451
        body = resp.json()
        assert body["decision"] == "BLOCK"
        assert body["risk_level"] == "SECRET_FOUND"

    def test_blocked_response_contains_full_scan_result(self):
        """Caller must be able to display why the file was blocked."""
        with patch("compliance_scan.api.scan.run_scan") as mock_scan, \
             patch("compliance_scan.api.scan.write_event"):
            mock_scan.return_value = ScanResult(
                filename="evil.pdf",
                file_type_detected="application/x-dosexec",
                file_type_declared="application/pdf",
                extension_mismatch=True,
                risk_level=RiskLevel.STRUCTURAL_ANOMALY,
                decision=Decision.BLOCK,
                anomaly_matches=[_high_anomaly_hit()],
            )
            resp = _upload(b"MZ\x90\x00", filename="evil.pdf")
        assert resp.status_code == 451
        body = resp.json()
        assert body["extension_mismatch"] is True
        assert len(body["anomaly_matches"]) == 1

    def test_unsupported_extension_returns_415(self):
        resp = client.post(
            "/scan",
            data={"user_id": "test-user"},
            files={"file": ("doc.mp4", io.BytesIO(b"garbage"), "video/mp4")},
        )
        assert resp.status_code == 415
