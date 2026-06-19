# compliance-pre-scan

> Local, LLM-free pre-upload compliance scanner for enterprise chat platforms.  
> Runs **before** any file reaches the LLM agent — flags sensitive data, credentials, and suspicious content, then writes an immutable audit trail.

---

## What this is

When a user uploads a file to the chat platform, this service intercepts it and runs a multi-layer scan:

1. **File identity check** — validates MIME type vs. declared extension (catches disguised payloads)
2. **Text extraction** — pulls raw text from PDF, DOCX, XLSX, TXT, RTF
3. **PII detection** — finds names, emails, IBANs, phone numbers, tax IDs, etc. (via Microsoft Presidio, regex-only mode, no NLP models needed)
4. **Secret / credential scanning** — detects API keys, tokens, DB connection strings (via Gitleaks-style regex ruleset)
5. **Custom keyword matching** — organisation-specific terms: project names, internal IDs, confidentiality markers (e.g. "Geheimhaltung", "EVB-IT", "Betriebsrat")
6. **Structural anomaly heuristics** — entropy check, size-vs-text ratio, extension mismatch, embedded macros
7. **Policy decision** — maps scan results to a risk level and decision (ALLOW / ALLOW_WITH_WARNING / BLOCK)
8. **Audit event log** — every scan, decision, and manual override is appended as an immutable SQLite row
9. **Betriebsrat CSV export** — date-range filtered export with pseudonymised user info and masked match snippets

No LLMs are used at any point. All processing is local.

---

## Supported file types (v1)

| Format | Extractor |
|--------|-----------|
| PDF    | `pymupdf` (fitz) |
| DOCX   | `python-docx` |
| XLSX   | `openpyxl` |
| TXT    | built-in |
| RTF    | `striprtf` |

---

## Tech stack

| Layer | Choice | Rationale |
|-------|--------|-----------|
| API service | FastAPI | Consistent with rest of platform |
| PII detection | [Microsoft Presidio](https://github.com/microsoft/presidio) | MIT license, regex-only mode, GDPR-focused recognisers |
| Secret scanning | Custom regex ruleset (Gitleaks-inspired) | MIT, embeddable, no daemon required |
| File type detection | `puremagic` | Pure Python, MIT, zero C deps — suitable for local Windows/Linux deployment |
| Anomaly heuristics | Custom (entropy, size ratio, macro detection) | No external dependency |
| Audit storage | SQLite via `aiosqlite` | Lightweight, local, zero-config, easy to swap for Postgres later |
| Policy engine | Inline Python (pluggable to OPA later) | Start simple, externalise when rules grow |

> **Note on ClamAV / YARA**: Both were evaluated but dropped for v1.  
> ClamAV requires a system daemon (not suitable for local deployments on customer machines).  
> YARA's rule sets are GPLv2, which complicates embedding. Both are listed as optional extensions in Phase 6.

---

## Repository structure (target end-state)

```
compliance-pre-scan/
├── README.md
├── pyproject.toml              # uv-managed dependencies
├── .env.example
│
├── src/
│   └── compliance_scan/
│       ├── __init__.py
│       ├── main.py             # FastAPI app entry point
│       │
│       ├── extractors/         # Phase 1 — text extraction per file type
│       │   ├── base.py
│       │   ├── pdf.py
│       │   ├── docx.py
│       │   ├── xlsx.py
│       │   ├── txt.py
│       │   └── rtf.py
│       │
│       ├── scanners/           # Phase 2 — detection modules
│       │   ├── file_identity.py    # MIME vs extension check
│       │   ├── pii.py              # Presidio-based PII detection
│       │   ├── secrets.py          # Credential / token regex scanner
│       │   ├── keywords.py         # Custom keyword / regex lists
│       │   └── anomalies.py        # Entropy, size ratio, macro detection
│       │
│       ├── policy/             # Phase 3 — risk level + decision logic
│       │   └── engine.py
│       │
│       ├── audit/              # Phase 4 — event log + export
│       │   ├── db.py               # SQLite schema + aiosqlite helpers
│       │   ├── models.py           # Pydantic models: ScanResult, RuleHit, AuditEvent
│       │   └── export.py           # CSV export for Betriebsrat
│       │
│       └── api/                # Phase 5 — HTTP endpoints
│           ├── scan.py             # POST /scan
│           └── compliance.py       # GET /compliance/events, GET /compliance/export
│
├── rules/
│   ├── keywords/
│   │   ├── hr.yaml             # HR / Betriebsrat terms
│   │   ├── finance.yaml        # Finance / IBAN / Steuer terms
│   │   └── confidentiality.yaml
│   └── secrets/
│       └── patterns.yaml       # Gitleaks-style credential patterns
│
└── tests/
    ├── test_extractors.py
    ├── test_scanners.py
    ├── test_policy.py
    └── fixtures/               # Sample files for each supported type
```

---

## Development phases

### Phase 1 — Text extraction + file identity (Sprint 1)
- [ ] Set up FastAPI skeleton + uv project
- [ ] Implement extractor for each file type (PDF, DOCX, XLSX, TXT, RTF)
- [ ] Implement `file_identity.py`: `puremagic` MIME detection, extension mismatch flag
- [ ] Unit tests with fixture files

### Phase 2 — Scanners (Sprint 2)
- [ ] `pii.py`: Presidio `AnalyzerEngine` in regex-only mode, German + English recognisers (IBAN, Steuernummer, phone, email, name)
- [ ] `secrets.py`: YAML-driven regex patterns (API keys, JWTs, DB URIs, AWS keys, generic passwords)
- [ ] `keywords.py`: YAML-driven keyword lists per domain (HR, finance, confidentiality)
- [ ] `anomalies.py`: Shannon entropy on raw bytes, size/text ratio, macro presence (DOCX/XLSX OLE check), extension mismatch escalation
- [ ] Unit tests for each scanner

### Phase 3 — Policy engine (Sprint 3)
- [ ] Define `RiskLevel` enum: `CLEAN`, `SENSITIVE_PII`, `SECRET_FOUND`, `STRUCTURAL_ANOMALY`
- [ ] Define `Decision` enum: `ALLOW`, `ALLOW_WITH_WARNING`, `BLOCK`
- [ ] Implement decision rules (configurable via `.env` thresholds):
  - `SECRET_FOUND` → `ALLOW_WITH_WARNING` (warn, do not block in v1)
  - `pii_count > threshold` → `ALLOW_WITH_WARNING`
  - `STRUCTURAL_ANOMALY` → `ALLOW_WITH_WARNING`
  - All else → `ALLOW`
- [ ] Unit tests for policy combinations

### Phase 4 — Audit trail (Sprint 4)
- [ ] SQLite schema: `compliance_events` + `compliance_rule_hits`
- [ ] Async write on every scan via `aiosqlite`
- [ ] CSV export endpoint with date-range + user filter, masked match snippets
- [ ] Integration test: scan → event written → export includes event

### Phase 5 — API + integration (Sprint 5)
- [ ] `POST /scan` — accepts file bytes + metadata, returns `ScanResult`
- [ ] `GET /compliance/events` — paginated event list (for compliance module UI tab)
- [ ] `GET /compliance/export` — CSV download for Betriebsrat
- [ ] OpenAPI schema auto-generated by FastAPI
- [ ] End-to-end test with sample files

### Phase 6 — Optional extensions
- [ ] ClamAV integration via `clamd` TCP socket (for deployments that can run a daemon)
- [ ] OPA/Rego policy externalisation
- [ ] Streamlit demo UI (scan dashboard + event viewer)

---

## Data models (overview)

```python
# ScanResult — returned from POST /scan
{
  "upload_id": "uuid",
  "filename": "contract.pdf",
  "file_type_detected": "application/pdf",
  "file_type_declared": "application/pdf",
  "extension_mismatch": false,
  "risk_level": "SENSITIVE_PII",        # worst level across all scanners
  "decision": "ALLOW_WITH_WARNING",
  "pii_matches": [...],                  # list of RuleHit
  "secret_matches": [...],
  "keyword_matches": [...],
  "anomalies": [...],
  "scan_duration_ms": 142
}

# RuleHit — one finding from any scanner
{
  "scanner": "PII",                      # PII | SECRET | KEYWORD | ANOMALY
  "rule_id": "PRESIDIO_IBAN",
  "entity_type": "IBAN",
  "severity": "HIGH",
  "location": {"page": 2, "offset": 1042},
  "match_snippet": "DE89 **** **** 3704 **** 02"  # masked
}

# AuditEvent — one immutable row in compliance_events
{
  "id": "uuid",
  "timestamp": "2026-06-19T09:20:00Z",
  "user_id": "u_123",
  "session_id": "s_456",
  "upload_id": "uuid",
  "filename_hash": "sha256:...",         # never store raw filename in audit log
  "action": "PRE_SCAN_COMPLETED",
  "risk_level": "SENSITIVE_PII",
  "decision": "ALLOW_WITH_WARNING",
  "pii_count": 3,
  "secret_count": 0,
  "anomaly_flags": "[]",
  "scan_duration_ms": 142
}
```

---

## Audit trail schema (SQLite)

```sql
CREATE TABLE compliance_events (
    id               TEXT PRIMARY KEY,
    timestamp        TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    session_id       TEXT,
    upload_id        TEXT NOT NULL,
    filename_hash    TEXT NOT NULL,
    action           TEXT NOT NULL,
    risk_level       TEXT NOT NULL,
    decision         TEXT NOT NULL,
    pii_count        INTEGER DEFAULT 0,
    secret_count     INTEGER DEFAULT 0,
    anomaly_flags    TEXT DEFAULT '[]',
    scan_duration_ms INTEGER
);

CREATE TABLE compliance_rule_hits (
    id          TEXT PRIMARY KEY,
    event_id    TEXT NOT NULL REFERENCES compliance_events(id),
    scanner     TEXT NOT NULL,
    rule_id     TEXT NOT NULL,
    entity_type TEXT,
    severity    TEXT NOT NULL,
    page_num    INTEGER,
    offset_char INTEGER,
    snippet     TEXT          -- masked, max 40 chars
);
```

---

## Betriebsrat CSV export columns

| Column | Notes |
|--------|-------|
| `timestamp` | ISO 8601 |
| `user_id_pseudonym` | SHA-256 of user_id (configurable: real ID for authorised exports) |
| `risk_level` | `CLEAN` / `SENSITIVE_PII` / `SECRET_FOUND` / `STRUCTURAL_ANOMALY` |
| `decision` | `ALLOW` / `ALLOW_WITH_WARNING` |
| `pii_count` | integer |
| `secret_count` | integer |
| `anomaly_flags` | JSON array of flag names |
| `top_rule_hits` | semicolon-separated masked snippets, max 5 |

Raw content and full filenames are **never** included in the export.

---

## Quick start (once Phase 1 is done)

```bash
# clone and install
git clone https://github.com/anbilly19/compliance-pre-scan
cd compliance-pre-scan
uv sync

# run
uv run fastapi dev src/compliance_scan/main.py

# hit the scan endpoint
curl -X POST http://localhost:8000/scan \
  -F "file=@./tests/fixtures/sample_contract.pdf" \
  -F "user_id=u_001" \
  -F "session_id=s_001"
```

---

## License

MIT — all core dependencies (Presidio, puremagic, FastAPI, aiosqlite) are MIT-licensed.  
Gitleaks-inspired secret patterns are written from scratch to avoid GPL contamination.
