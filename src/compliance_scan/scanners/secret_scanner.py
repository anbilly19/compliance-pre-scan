"""Secret / credential detection via pure-Python regex rules (no GPL deps)."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..audit.models import RuleHit


@dataclass
class _Rule:
    rule_id: str
    pattern: re.Pattern
    severity: str = "HIGH"
    description: str = ""


_RULES: list[_Rule] = [
    _Rule("AWS_ACCESS_KEY",     re.compile(r"(?<![A-Z0-9])(AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}(?![A-Z0-9])"),          "HIGH"),
    _Rule("AWS_SECRET_KEY",     re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),               "HIGH"),
    _Rule("GITHUB_TOKEN",       re.compile(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}"),                       "HIGH"),
    _Rule("GENERIC_API_KEY",    re.compile(r"(?i)(api[_\-\s]?key|apikey)[\s:=]+['\"]?([A-Za-z0-9\-_]{20,})['\"]?"),   "HIGH"),
    _Rule("BEARER_TOKEN",       re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}"),                                    "HIGH"),
    _Rule("PRIVATE_KEY_BLOCK",  re.compile(r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----"),                              "HIGH"),
    _Rule("GENERIC_PASSWORD",   re.compile(r"(?i)(password|passwd|pwd)[\s:=]+['\"]?[^\s'\"]{8,}['\"]?"),               "MEDIUM"),
    _Rule("DB_CONNECTION_STR",  re.compile(r"(?i)(mysql|postgresql|mongodb|mssql)://[^\s@]+:[^\s@]+@[^\s]+"),          "HIGH"),
    _Rule("JWT_TOKEN",          re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),        "HIGH"),
    _Rule("AZURE_CONN_STR",     re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[^;]+"),      "HIGH"),
    _Rule("SLACK_TOKEN",        re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}"),                                         "HIGH"),
]


class SecretScanner:
    def __init__(self, extra_rules: list[_Rule] | None = None) -> None:
        self._rules = _RULES + (extra_rules or [])

    def scan(self, text: str) -> list[RuleHit]:
        hits: list[RuleHit] = []
        for rule in self._rules:
            for m in rule.pattern.finditer(text):
                raw = m.group(0)
                # Aggressive masking: show first 4 chars only
                masked = raw[:4] + "*" * min(len(raw) - 4, 20)
                hits.append(RuleHit(
                    scanner="SECRET",
                    rule_id=rule.rule_id,
                    entity_type=rule.rule_id,
                    severity=rule.severity,
                    offset_char=m.start(),
                    match_snippet=masked,
                ))
        return hits
