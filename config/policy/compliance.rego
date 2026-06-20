# compliance.rego — OPA policy for pre-upload compliance scanning
#
# Input fields (all supplied by the Python policy engine):
#   pii_count, secret_count, keyword_count, high_anomaly_count
#   pii_warn_threshold, secret_warn_threshold
#   block_on_secret, block_on_pii, block_on_structural_anomaly
#
# Output (data.compliance.decision):
#   { "risk_level": string, "decision": string, "reason": string }
#
# Priority: BLOCK > ALLOW_WITH_WARNING > ALLOW

package compliance

import rego.v1

# ── default ──────────────────────────────────────────────────────────────────

default decision := {"risk_level": "CLEAN", "decision": "ALLOW", "reason": "clean"}

# ── BLOCK rules (highest priority) ───────────────────────────────────────────

decision := {"risk_level": "SECRET_FOUND", "decision": "BLOCK", "reason": "block_on_secret"} if {
    input.block_on_secret > 0
    input.secret_count >= input.block_on_secret
}

decision := {"risk_level": "SENSITIVE_PII", "decision": "BLOCK", "reason": "block_on_pii"} if {
    input.block_on_pii > 0
    input.pii_count >= input.block_on_pii
    not _secret_blocked
}

decision := {"risk_level": "STRUCTURAL_ANOMALY", "decision": "BLOCK", "reason": "block_on_structural_anomaly"} if {
    input.block_on_structural_anomaly == true
    input.high_anomaly_count > 0
    not _secret_blocked
    not _pii_blocked
}

# ── ALLOW_WITH_WARNING rules ──────────────────────────────────────────────────

decision := {"risk_level": "SECRET_FOUND", "decision": "ALLOW_WITH_WARNING", "reason": "secret_warn"} if {
    input.secret_count >= input.secret_warn_threshold
    not _any_block
}

decision := {"risk_level": "SENSITIVE_PII", "decision": "ALLOW_WITH_WARNING", "reason": "pii_warn"} if {
    input.pii_count >= input.pii_warn_threshold
    not _any_block
    not _secret_warned
}

decision := {"risk_level": "SENSITIVE_PII", "decision": "ALLOW_WITH_WARNING", "reason": "keyword_match"} if {
    input.keyword_count > 0
    not _any_block
    not _secret_warned
    not _pii_warned
}

decision := {"risk_level": "STRUCTURAL_ANOMALY", "decision": "ALLOW_WITH_WARNING", "reason": "high_anomaly"} if {
    input.high_anomaly_count > 0
    not input.block_on_structural_anomaly
    not _any_block
    not _secret_warned
    not _pii_warned
}

# ── helpers (not exported) ────────────────────────────────────────────────────

_secret_blocked if {
    input.block_on_secret > 0
    input.secret_count >= input.block_on_secret
}

_pii_blocked if {
    input.block_on_pii > 0
    input.pii_count >= input.block_on_pii
}

_any_block if { _secret_blocked }
_any_block if { _pii_blocked }
_any_block if {
    input.block_on_structural_anomaly == true
    input.high_anomaly_count > 0
}

_secret_warned if {
    input.secret_count >= input.secret_warn_threshold
}

_pii_warned if {
    input.pii_count >= input.pii_warn_threshold
}
