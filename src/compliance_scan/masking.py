"""Snippet masking for production mode.

When settings.mask_snippets is True, match_snippet values in RuleHit objects
are masked so that sensitive values are not stored in the audit DB or returned
in API responses in plain text.

Masking strategy per scanner type:
  PII     — keep first 2 + last 2 chars, replace middle with ***
  SECRET  — keep first 4 chars only, replace rest with ****
  KEYWORD — pass through unchanged (the keyword itself is not sensitive payload)
  ANOMALY — pass through unchanged (MIME type names / heuristic labels)

When settings.mask_snippets is False (default for dev/test), all functions
are no-ops and return the input unchanged.
"""
from __future__ import annotations

from .audit.models import RuleHit, ScanResult
from .config import settings

_PII_KEEP_START = 2
_PII_KEEP_END   = 2
_SECRET_KEEP    = 4


def mask_snippet(snippet: str, scanner: str) -> str:
    """Return a masked version of a single match_snippet string."""
    if not settings.mask_snippets or not snippet:
        return snippet

    s = scanner.upper()
    if s == "SECRET":
        return _mask_secret(snippet)
    if s == "PII":
        return _mask_pii(snippet)
    return snippet  # KEYWORD, ANOMALY — pass through


def mask_rule_hit(hit: RuleHit) -> RuleHit:
    """Return a copy of hit with match_snippet masked (original not mutated)."""
    if not settings.mask_snippets:
        return hit
    return hit.model_copy(
        update={"match_snippet": mask_snippet(hit.match_snippet, hit.scanner)}
    )


def mask_result(result: ScanResult) -> ScanResult:
    """Return a copy of result with all match_snippets masked.

    Called at the end of pipeline.run_scan() so masked snippets are what
    gets written to the audit DB and returned by the API endpoint.
    """
    if not settings.mask_snippets:
        return result
    return result.model_copy(update={
        "pii_matches":     [mask_rule_hit(h) for h in result.pii_matches],
        "secret_matches":  [mask_rule_hit(h) for h in result.secret_matches],
        "keyword_matches": [mask_rule_hit(h) for h in result.keyword_matches],
        "anomaly_matches": [mask_rule_hit(h) for h in result.anomaly_matches],
    })


# ── internal helpers ──────────────────────────────────────────────────────────

def _mask_pii(snippet: str) -> str:
    """Keep first 2 and last 2 characters; replace middle with ***.

    Examples
    --------
    'max.mustermann@firma.de'  -> 'ma***de'
    'DE89370400440532013000'   -> 'DE***00'
    '+4921112345'              -> '+4***45'
    'abcd' (exactly 4 chars)   -> '***'
    """
    s = snippet.strip()
    if len(s) <= _PII_KEEP_START + _PII_KEEP_END:
        return "***"
    return s[:_PII_KEEP_START] + "***" + s[-_PII_KEEP_END:]


def _mask_secret(snippet: str) -> str:
    """Keep first 4 characters only; replace rest with ****.

    Examples
    --------
    'AKIAIOSFODNN7EXAMPLE'                      -> 'AKIA****'
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9'    -> 'eyJh****'
    'sk' (shorter than 4)                       -> '****'
    """
    s = snippet.strip()
    if len(s) <= _SECRET_KEEP:
        return "****"
    return s[:_SECRET_KEEP] + "****"
