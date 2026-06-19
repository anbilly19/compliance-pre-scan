"""Unit tests for individual scanners."""
from compliance_scan.scanners.secret_scanner import SecretScanner
from compliance_scan.scanners.keyword_scanner import KeywordScanner
from compliance_scan.scanners.anomaly_scanner import AnomalyScanner
from compliance_scan.scanners.file_identity import identify_file


class TestSecretScanner:
    def setup_method(self):
        self.scanner = SecretScanner()

    def test_detects_aws_key(self):
        text = "export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        hits = self.scanner.scan(text)
        assert any(h.rule_id == "AWS_ACCESS_KEY" for h in hits)

    def test_detects_jwt(self):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        hits = self.scanner.scan(token)
        assert any(h.rule_id == "JWT_TOKEN" for h in hits)

    def test_detects_private_key(self):
        hits = self.scanner.scan("-----BEGIN RSA PRIVATE KEY-----\nMIIE...")
        assert any(h.rule_id == "PRIVATE_KEY_BLOCK" for h in hits)

    def test_no_false_positive_on_clean_text(self):
        hits = self.scanner.scan("This is a clean document with no secrets.")
        assert hits == []


class TestKeywordScanner:
    def setup_method(self):
        self.scanner = KeywordScanner()

    def test_detects_confidential(self):
        hits = self.scanner.scan("STRICTLY CONFIDENTIAL - do not distribute")
        assert any("confidential_labels" in h.entity_type for h in hits)

    def test_detects_german_keyword(self):
        hits = self.scanner.scan("Betrifft: Personalakte Hr. Mustermann")
        assert any(h.entity_type == "betriebsrat_sensitive" for h in hits)

    def test_clean_text(self):
        hits = self.scanner.scan("Meeting notes from Monday")
        assert hits == []


class TestFileIdentity:
    def test_txt_file(self, tmp_path):
        f = tmp_path / "readme.txt"
        f.write_text("hello", encoding="utf-8")
        identity = identify_file(f)
        assert identity.mime_from_extension == "text/plain"
