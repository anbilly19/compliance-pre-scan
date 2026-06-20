"""Phase 10 — tests for BLOCK decision enforcement.

Covers:
- policy engine returns BLOCK for secrets when block_on_secret > 0
- policy engine returns BLOCK for structural anomalies when block_on_structural_anomaly=True
- policy engine returns ALLOW_WITH_WARNING (not BLOCK) when block thresholds are at 0/False
- POST /scan returns HTTP 451 when decision == BLOCK
- POST /scan returns HTTP 200 when decision is ALLOW or ALLOW_WITH_WARNING
- POST /scan returns HTTP 415 for unsupported file types

Note: _derive_decision was removed in Phase 12 and replaced by the policy engine
(compliance_scan.policy.engine). The unit tests below test the same logic via
_evaluate_inline + PolicyInput.

IMPORTANT: run_scan and write_event are imported directly into app.py, so patches
must target compliance_scan.api.app.run_scan and compliance_scan.api.app.write_event.
"""
import io
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from compliance_scan.api.app import app
from compliance_scan.audit.models import RiskLevel, Decision, RuleHit, ScanResult
from compliance_scan.policy.engine import PolicyInput, _evaluate_inline


# ── helpers ───────────────────────────────────────────────────────────────────

def _mock_settings(**overrides):
    m = MagicMock()
    m.pii_warn_threshold = 1
    m.secret_warn_threshold = 1
    m.block_on_secret = 1
    m.block_on_pii = 0
    m.block_on_structural_anomaly = False
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


def _secret_hit() -> RuleHit:
    return RuleHit(scanner="SECRET", rule_id="AWS_ACCESS_KEY", severity="HIGH", match_snippet="AKIA...")


def _high_anomaly_hit() -> RuleHit:
    return RuleHit(scanner="ANOMALY", rule_id="FILE_IDENTITY_MISMATCH", severity="HIGH", match_snippet="ext mismatch")


def _pii_hit() -> RuleHit:
    return RuleHit(scanner="PII", rule_id="EMAIL_ADDRESS", severity="HIGH", match_snippet="u@e.de")


# ── unit tests: policy engine block behaviour ───────────────────────────────────────

class TestPolicyEngineBlock:

    def test_secret_triggers_block_when_threshold_1(self):
        with patch("compliance_scan.policy.engine.settings",
                   _mock_settings(block_on_secret=1)):
            result = _evaluate_inline(PolicyInput(secret_count=1))
        assert result.decision == Decision.BLOCK
        assert result.risk_level == RiskLevel.SECRET_FOUND

    def test_no_block_when_block_on_secret_zero(self):
        with patch("compliance_scan.policy.engine.settings",
                   _mock_settings(block_on_secret=0)):
            result = _evaluate_inline(PolicyInput(secret_count=1))
        assert result.decision == Decision.ALLOW_WITH_WARNING

    def test_structural_anomaly_blocks_when_enabled(self):
        with patch("compliance_scan.policy.engine.settings",
                   _mock_settings(block_on_secret=0, block_on_structural_anomaly=True)):
            result = _evaluate_inline(PolicyInput(high_anomaly_count=1))
        assert result.decision == Decision.BLOCK
        assert result.risk_level == RiskLevel.STRUCTURAL_ANOMALY

    def test_structural_anomaly_warns_only_when_disabled(self):
        with patch("compliance_scan.policy.engine.settings",
                   _mock_settings(block_on_secret=0, block_on_structural_anomaly=False)):
            result = _evaluate_inline(PolicyInput(high_anomaly_count=1))
        assert result.decision == Decision.ALLOW_WITH_WARNING

    def test_pii_block_threshold_respected(self):
        with patch("compliance_scan.policy.engine.settings",
                   _mock_settings(block_on_secret=0, block_on_pii=5)):
            result = _evaluate_inline(PolicyInput(pii_count=5))
        assert result.decision == Decision.BLOCK

    def test_clean_file_allowed(self):
        with patch("compliance_scan.policy.engine.settings",
                   _mock_settings(block_on_secret=1, block_on_structural_anomaly=True)):
            result = _evaluate_inline(PolicyInput())
        assert result.decision == Decision.ALLOW
        assert result.risk_level == RiskLevel.CLEAN


# ── integration tests: POST /scan HTTP status codes ────────────────────────────
#
# run_scan and write_event are imported directly in app.py, so patches must
# target compliance_scan.api.app.<name>, not compliance_scan.api.scan.<name>.
#
# write_event is async — must use AsyncMock or the await in the handler
# silently swallows the mock and the endpoint returns 200 regardless.

client = TestClient(app, raise_server_exceptions=False)


def _upload(content: bytes, filename: str = "test.txt"):
    return client.post(
        "/scan",
        data={"user_id": "test-user", "session_id": "test-session"},
        files={"file": (filename, io.BytesIO(content), "text/plain")},
    )


class TestScanEndpointStatusCodes:

    def test_clean_file_returns_200(self):
        with patch("compliance_scan.api.app.run_scan") as mock_scan, \
             patch("compliance_scan.api.app.write_event", new_callable=AsyncMock):
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
        with patch("compliance_scan.api.app.run_scan") as mock_scan, \
             patch("compliance_scan.api.app.write_event", new_callable=AsyncMock):
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
        with patch("compliance_scan.api.app.run_scan") as mock_scan, \
             patch("compliance_scan.api.app.write_event", new_callable=AsyncMock):
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
        with patch("compliance_scan.api.app.run_scan") as mock_scan, \
             patch("compliance_scan.api.app.write_event", new_callable=AsyncMock):
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
