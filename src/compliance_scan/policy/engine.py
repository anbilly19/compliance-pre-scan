"""Policy engine: evaluate scan hits → (RiskLevel, Decision).

Two backends, selected by config:

1. OPA (Open Policy Agent) — active when settings.opa_url is set.
   Sends a PolicyInput JSON to POST {opa_url}/v1/data/compliance/decision
   and parses the Rego result.

2. Inline Python fallback — used when OPA is not configured (default).
   Implements the same logic as the Rego policy so behaviour is identical.

Both backends return a PolicyResult with (risk_level, decision, reason).
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from ..audit.models import RiskLevel, Decision
from ..config import settings

log = logging.getLogger(__name__)


@dataclass
class PolicyInput:
    """Normalised input document sent to the policy engine."""
    pii_count: int = 0
    secret_count: int = 0
    keyword_count: int = 0
    high_anomaly_count: int = 0


@dataclass
class PolicyResult:
    risk_level: RiskLevel
    decision: Decision
    reason: str = ""


def evaluate(inp: PolicyInput) -> PolicyResult:
    """Evaluate a PolicyInput and return a PolicyResult.

    Routes to OPA when settings.opa_url is configured, otherwise falls back
    to the inline Python implementation.
    """
    if settings.opa_url:
        try:
            return _evaluate_opa(inp)
        except Exception as exc:
            log.error("OPA evaluation failed (%s); falling back to inline policy", exc)
    return _evaluate_inline(inp)


# ── OPA backend ──────────────────────────────────────────────────────────────

def _evaluate_opa(inp: PolicyInput) -> PolicyResult:
    """POST input to OPA and parse the compliance/decision result."""
    import httpx

    url = f"{settings.opa_url.rstrip('/')}/v1/data/compliance/decision"
    payload = {
        "input": {
            "pii_count":          inp.pii_count,
            "secret_count":       inp.secret_count,
            "keyword_count":      inp.keyword_count,
            "high_anomaly_count": inp.high_anomaly_count,
            # thresholds from config — passed as input so Rego rules are threshold-agnostic
            "pii_warn_threshold":          settings.pii_warn_threshold,
            "secret_warn_threshold":       settings.secret_warn_threshold,
            "block_on_secret":             settings.block_on_secret,
            "block_on_pii":                settings.block_on_pii,
            "block_on_structural_anomaly": settings.block_on_structural_anomaly,
        }
    }
    log.debug("OPA request url=%s input=%s", url, payload["input"])
    resp = httpx.post(url, json=payload, timeout=settings.opa_timeout_s)
    resp.raise_for_status()

    result = resp.json().get("result", {})
    log.debug("OPA response result=%s", result)

    risk_raw     = result.get("risk_level", "CLEAN")
    decision_raw = result.get("decision",   "ALLOW")
    reason       = result.get("reason",     "")

    try:
        risk_level = RiskLevel(risk_raw)
    except ValueError:
        log.warning("OPA returned unknown risk_level %r; defaulting to CLEAN", risk_raw)
        risk_level = RiskLevel.CLEAN

    try:
        decision = Decision(decision_raw)
    except ValueError:
        log.warning("OPA returned unknown decision %r; defaulting to ALLOW", decision_raw)
        decision = Decision.ALLOW

    return PolicyResult(risk_level=risk_level, decision=decision, reason=reason)


# ── Inline Python fallback ────────────────────────────────────────────────────

def _evaluate_inline(inp: PolicyInput) -> PolicyResult:
    """Pure-Python mirror of the Rego policy in config/policy/compliance.rego.

    Priority: BLOCK > ALLOW_WITH_WARNING > ALLOW
    Highest-severity match wins.
    """
    risk     = RiskLevel.CLEAN
    decision = Decision.ALLOW
    reason   = ""

    # Structural anomalies
    if inp.high_anomaly_count > 0:
        risk     = RiskLevel.STRUCTURAL_ANOMALY
        decision = Decision.ALLOW_WITH_WARNING
        reason   = "high_anomaly"
        if settings.block_on_structural_anomaly:
            decision = Decision.BLOCK
            reason   = "block_on_structural_anomaly"

    # Secrets
    if inp.secret_count >= settings.secret_warn_threshold:
        if risk == RiskLevel.CLEAN:
            risk = RiskLevel.SECRET_FOUND
        if decision == Decision.ALLOW:
            decision = Decision.ALLOW_WITH_WARNING
            reason   = "secret_warn"

    if settings.block_on_secret > 0 and inp.secret_count >= settings.block_on_secret:
        risk     = RiskLevel.SECRET_FOUND
        decision = Decision.BLOCK
        reason   = "block_on_secret"

    # PII
    if inp.pii_count >= settings.pii_warn_threshold:
        if risk == RiskLevel.CLEAN:
            risk = RiskLevel.SENSITIVE_PII
        if decision == Decision.ALLOW:
            decision = Decision.ALLOW_WITH_WARNING
            reason   = "pii_warn"

    if settings.block_on_pii > 0 and inp.pii_count >= settings.block_on_pii:
        risk     = RiskLevel.SENSITIVE_PII
        decision = Decision.BLOCK
        reason   = "block_on_pii"

    # Keywords
    if inp.keyword_count > 0 and decision == Decision.ALLOW:
        if risk == RiskLevel.CLEAN:
            risk = RiskLevel.SENSITIVE_PII
        decision = Decision.ALLOW_WITH_WARNING
        reason   = "keyword_match"

    return PolicyResult(risk_level=risk, decision=decision, reason=reason)
