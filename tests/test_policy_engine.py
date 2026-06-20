"""Phase 12 — tests for the policy engine (OPA + inline fallback).

Covers:
- _evaluate_inline: all rule paths (clean, warn, block per category)
- _evaluate_inline: priority ordering (BLOCK beats WARN)
- evaluate(): routes to inline when opa_url is None
- evaluate(): falls back to inline when OPA call raises
- evaluate(): parses OPA response correctly (mocked httpx)
"""
from unittest.mock import MagicMock, patch

import pytest

from compliance_scan.audit.models import RiskLevel, Decision
from compliance_scan.policy.engine import PolicyInput, PolicyResult, _evaluate_inline, evaluate


# ── helpers ───────────────────────────────────────────────────────────────────

def _settings(**overrides):
    m = MagicMock()
    m.pii_warn_threshold = 1
    m.secret_warn_threshold = 1
    m.block_on_secret = 1
    m.block_on_pii = 0
    m.block_on_structural_anomaly = True
    m.opa_url = None
    m.opa_timeout_s = 2.0
    for k, v in overrides.items():
        setattr(m, k, v)
    return m


# ── _evaluate_inline ──────────────────────────────────────────────────────────

class TestEvaluateInline:
    def test_clean(self):
        with patch("compliance_scan.policy.engine.settings", _settings()):
            r = _evaluate_inline(PolicyInput())
        assert r.decision == Decision.ALLOW
        assert r.risk_level == RiskLevel.CLEAN

    def test_secret_warn(self):
        with patch("compliance_scan.policy.engine.settings", _settings(block_on_secret=0)):
            r = _evaluate_inline(PolicyInput(secret_count=1))
        assert r.decision == Decision.ALLOW_WITH_WARNING
        assert r.risk_level == RiskLevel.SECRET_FOUND

    def test_secret_block(self):
        with patch("compliance_scan.policy.engine.settings", _settings(block_on_secret=1)):
            r = _evaluate_inline(PolicyInput(secret_count=1))
        assert r.decision == Decision.BLOCK
        assert r.risk_level == RiskLevel.SECRET_FOUND

    def test_pii_warn(self):
        with patch("compliance_scan.policy.engine.settings", _settings(block_on_secret=0)):
            r = _evaluate_inline(PolicyInput(pii_count=1))
        assert r.decision == Decision.ALLOW_WITH_WARNING
        assert r.risk_level == RiskLevel.SENSITIVE_PII

    def test_pii_block(self):
        with patch("compliance_scan.policy.engine.settings", _settings(block_on_pii=3)):
            r = _evaluate_inline(PolicyInput(pii_count=3))
        assert r.decision == Decision.BLOCK

    def test_keyword_warn(self):
        with patch("compliance_scan.policy.engine.settings", _settings(block_on_secret=0)):
            r = _evaluate_inline(PolicyInput(keyword_count=1))
        assert r.decision == Decision.ALLOW_WITH_WARNING

    def test_anomaly_warn_when_block_disabled(self):
        with patch("compliance_scan.policy.engine.settings",
                   _settings(block_on_structural_anomaly=False, block_on_secret=0)):
            r = _evaluate_inline(PolicyInput(high_anomaly_count=1))
        assert r.decision == Decision.ALLOW_WITH_WARNING
        assert r.risk_level == RiskLevel.STRUCTURAL_ANOMALY

    def test_anomaly_block_when_enabled(self):
        with patch("compliance_scan.policy.engine.settings",
                   _settings(block_on_structural_anomaly=True, block_on_secret=0)):
            r = _evaluate_inline(PolicyInput(high_anomaly_count=1))
        assert r.decision == Decision.BLOCK

    def test_block_beats_warn(self):
        with patch("compliance_scan.policy.engine.settings",
                   _settings(block_on_secret=1, block_on_pii=0)):
            r = _evaluate_inline(PolicyInput(secret_count=1, pii_count=5))
        assert r.decision == Decision.BLOCK


# ── evaluate() routing ────────────────────────────────────────────────────────

class TestEvaluateRouting:
    def test_routes_to_inline_when_no_opa_url(self):
        with patch("compliance_scan.policy.engine.settings", _settings(opa_url=None)):
            r = evaluate(PolicyInput())
        assert r.decision == Decision.ALLOW

    def test_fallback_to_inline_on_opa_error(self):
        with patch("compliance_scan.policy.engine.settings",
                   _settings(opa_url="http://localhost:8181")), \
             patch("compliance_scan.policy.engine._evaluate_opa",
                   side_effect=Exception("connection refused")):
            r = evaluate(PolicyInput())
        assert r.decision == Decision.ALLOW

    def test_opa_response_parsed(self):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "result": {
                "risk_level": "SECRET_FOUND",
                "decision":   "BLOCK",
                "reason":     "block_on_secret",
            }
        }
        mock_resp.raise_for_status = MagicMock()

        with patch("compliance_scan.policy.engine.settings",
                   _settings(opa_url="http://localhost:8181")), \
             patch("httpx.post", return_value=mock_resp):
            r = evaluate(PolicyInput(secret_count=1))

        assert r.decision == Decision.BLOCK
        assert r.risk_level == RiskLevel.SECRET_FOUND
        assert r.reason == "block_on_secret"
