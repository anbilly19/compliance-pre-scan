"""Quick debug runner — run from the repo root.

    uv run python debug_scan.py path/to/file.pdf
    uv run python debug_scan.py tests/fixtures/sample.pdf

Outputs a scan summary to stdout AND writes full DEBUG log to logs/compliance_scan.log.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Configure logging BEFORE importing anything from compliance_scan
from compliance_scan.logging_setup import configure_logging
configure_logging(log_dir="logs", console_level=10)  # 10 = DEBUG on console too

from compliance_scan.pipeline import run_scan  # noqa: E402


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: uv run python debug_scan.py <file>")
        sys.exit(1)

    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        sys.exit(1)

    print(f"\nScanning: {path}\n" + "-" * 60)
    result = run_scan(path)

    print(f"Risk level : {result.risk_level}")
    print(f"Decision   : {result.decision}")
    print(f"Duration   : {result.scan_duration_ms} ms")
    print(f"MIME detect: {result.file_type_detected}")
    print(f"MIME ext   : {result.file_type_declared}")
    print(f"Mismatch   : {result.extension_mismatch}")
    print()

    if result.pii_matches:
        print(f"PII hits ({len(result.pii_matches)}):")
        for h in result.pii_matches:
            print(f"  [{h.severity}] {h.entity_type} @ char {h.offset_char}  snippet={h.match_snippet!r}")
    else:
        print("PII hits: none")

    if result.secret_matches:
        print(f"\nSecret hits ({len(result.secret_matches)}):")
        for h in result.secret_matches:
            print(f"  [{h.severity}] {h.rule_id} @ char {h.offset_char}  snippet={h.match_snippet!r}")
    else:
        print("Secret hits: none")

    if result.keyword_matches:
        print(f"\nKeyword hits ({len(result.keyword_matches)}):")
        for h in result.keyword_matches:
            print(f"  [{h.severity}] {h.entity_type}  snippet={h.match_snippet!r}")
    else:
        print("Keyword hits: none")

    if result.anomaly_matches:
        print(f"\nAnomaly hits ({len(result.anomaly_matches)}):")
        for h in result.anomaly_matches:
            print(f"  [{h.severity}] {h.rule_id}  snippet={h.match_snippet!r}")
    else:
        print("Anomaly hits: none")

    print(f"\nFull DEBUG log written to: logs/compliance_scan.log")


if __name__ == "__main__":
    main()
