"""Phase 11 — tests for hit masking.

Covers:
- mask_snippet(): PII format (keep first 2 + last 2)
- mask_snippet(): SECRET format (keep first 4 only)
- mask_snippet(): KEYWORD + ANOMALY pass-through
- mask_snippet(): edge cases (short strings, empty)
- mask_rule_hit(): respects mask_snippets flag; does not mutate original
- mask_result(): masks all four hit lists; does not mutate original; no-op on clean result
- mask_result(): no-op when mask_snippets=False
"""
from unittest.mock import patch

from compliance_scan.audit.models import RuleHit, ScanResult, RiskLevel, Decision
from compliance_scan.masking import mask_snippet, mask_rule_hit, mask_result


# ── helpers ───────────────────────────────────────────────────────────────────

def _hit(scanner: str, snippet: str) -> RuleHit:
    return RuleHit(scanner=scanner, rule_id="TEST", severity="HIGH", match_snippet=snippet)


def _result_with_hits() -> ScanResult:
    return ScanResult(
        filename="test.txt",
        file_type_detected="text/plain",
        file_type_declared="text/plain",
        risk_level=RiskLevel.SECRET_FOUND,
        decision=Decision.ALLOW_WITH_WARNING,
        pii_matches=[_hit("PII", "max.mustermann@firma.de")],
        secret_matches=[_hit("SECRET", "AKIAIOSFODNN7EXAMPLE")],
        keyword_matches=[_hit("KEYWORD", "CONFIDENTIAL")],
        anomaly_matches=[_hit("ANOMALY", "extension_mismatch: pdf vs exe")],
    )


# ── mask_snippet: PII ─────────────────────────────────────────────────────────

class TestMaskSnippetPII:
    def _mask(self, s):
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            return mask_snippet(s, "PII")

    def test_email(self):
        assert self._mask("max.mustermann@firma.de") == "ma***de"

    def test_iban(self):
        assert self._mask("DE89370400440532013000") == "DE***00"

    def test_phone(self):
        assert self._mask("+4921112345") == "+4***45"

    def test_exactly_four_chars_returns_stars(self):
        assert self._mask("abcd") == "***"

    def test_very_short(self):
        assert self._mask("ab") == "***"

    def test_empty(self):
        assert self._mask("") == ""


# ── mask_snippet: SECRET ──────────────────────────────────────────────────────

class TestMaskSnippetSecret:
    def _mask(self, s):
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            return mask_snippet(s, "SECRET")

    def test_aws_key(self):
        assert self._mask("AKIAIOSFODNN7EXAMPLE") == "AKIA****"

    def test_jwt(self):
        assert self._mask("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") == "eyJh****"

    def test_short_secret(self):
        assert self._mask("sk") == "****"

    def test_empty(self):
        assert self._mask("") == ""


# ── mask_snippet: pass-through types ─────────────────────────────────────────

class TestMaskSnippetPassthrough:
    def _mask(self, s, scanner):
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            return mask_snippet(s, scanner)

    def test_keyword_unchanged(self):
        assert self._mask("CONFIDENTIAL", "KEYWORD") == "CONFIDENTIAL"

    def test_anomaly_unchanged(self):
        assert self._mask("extension_mismatch: pdf vs exe", "ANOMALY") == "extension_mismatch: pdf vs exe"

    def test_lowercase_scanner_name(self):
        assert self._mask("CONFIDENTIAL", "keyword") == "CONFIDENTIAL"


# ── mask_snippet: disabled ────────────────────────────────────────────────────

class TestMaskSnippetDisabled:
    def test_no_masking_when_flag_false(self):
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = False
            result = mask_snippet("AKIAIOSFODNN7EXAMPLE", "SECRET")
        assert result == "AKIAIOSFODNN7EXAMPLE"


# ── mask_rule_hit ─────────────────────────────────────────────────────────────

class TestMaskRuleHit:
    def test_masks_secret(self):
        hit = _hit("SECRET", "AKIAIOSFODNN7EXAMPLE")
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            masked = mask_rule_hit(hit)
        assert masked.match_snippet == "AKIA****"

    def test_original_not_mutated(self):
        hit = _hit("SECRET", "AKIAIOSFODNN7EXAMPLE")
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            mask_rule_hit(hit)
        assert hit.match_snippet == "AKIAIOSFODNN7EXAMPLE"

    def test_other_fields_preserved(self):
        hit = _hit("PII", "test@example.com")
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            masked = mask_rule_hit(hit)
        assert masked.rule_id == "TEST"
        assert masked.severity == "HIGH"
        assert masked.scanner == "PII"

    def test_no_op_when_disabled(self):
        hit = _hit("SECRET", "AKIAIOSFODNN7EXAMPLE")
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = False
            assert mask_rule_hit(hit).match_snippet == "AKIAIOSFODNN7EXAMPLE"


# ── mask_result ───────────────────────────────────────────────────────────────

class TestMaskResult:
    def test_all_four_lists_masked(self):
        result = _result_with_hits()
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            masked = mask_result(result)
        assert masked.pii_matches[0].match_snippet     == "ma***de"
        assert masked.secret_matches[0].match_snippet  == "AKIA****"
        assert masked.keyword_matches[0].match_snippet == "CONFIDENTIAL"
        assert masked.anomaly_matches[0].match_snippet == "extension_mismatch: pdf vs exe"

    def test_original_not_mutated(self):
        result = _result_with_hits()
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            mask_result(result)
        assert result.pii_matches[0].match_snippet    == "max.mustermann@firma.de"
        assert result.secret_matches[0].match_snippet == "AKIAIOSFODNN7EXAMPLE"

    def test_no_op_when_disabled(self):
        result = _result_with_hits()
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = False
            masked = mask_result(result)
        assert masked.secret_matches[0].match_snippet == "AKIAIOSFODNN7EXAMPLE"

    def test_clean_result_unaffected(self):
        result = ScanResult(
            filename="clean.txt",
            file_type_detected="text/plain",
            file_type_declared="text/plain",
        )
        with patch("compliance_scan.masking.settings") as m:
            m.mask_snippets = True
            masked = mask_result(result)
        assert masked.pii_matches == []
        assert masked.secret_matches == []
