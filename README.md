# compliance-pre-scan

> Local, LLM-free pre-upload compliance scanner for enterprise chat platforms.  
> Runs **before** any file reaches the LLM agent — flags sensitive data, credentials, and suspicious content, then writes an immutable audit trail.

---

## Status

| Phase | Description | State |
|-------|-------------|-------|
| 1 | Text extraction + file identity | ✅ Done |
| 2 | PII, secret, keyword, anomaly scanners | ✅ Done |
| 3 | Policy engine (risk level + decision) | ✅ Done |
| 4 | Audit trail (SQLite + CSV export) | ✅ Done |
| 5 | FastAPI endpoints + Streamlit UI | ✅ Done |
| 6 | Logging (rotating file + console) | ✅ Done |
| 7 | False-positive suppression (technical + financial docs) | ✅ Done |
| 8 | ClamAV / YARA integration | ⬜ Planned |
| 9 | Manual breach report UI button | ⬜ Planned |
| 10 | BLOCK enforcement in chat layer | ⬜ Planned |
| 11 | Hit masking config flag (test vs production) | ⬜ Planned |
| 12 | OPA/Rego policy externalisation | ⬜ Planned |

---

## What this does

When a user selects a file for upload in the chat platform, this service intercepts it **before** it reaches the LLM agent and runs a multi-layer scan:

1. **File identity check** — validates MIME type vs. declared extension (catches disguised payloads, e.g. an `.exe` renamed to `.pdf`)
2. **Text extraction** — pulls raw text from PDF, DOCX, XLSX, TXT, RTF
3. **PII detection** — finds personal identifiers using Microsoft Presidio with bilingual EN + DE NER and regex recognisers
4. **Secret / credential scanning** — detects API keys, tokens, DB connection strings, passwords via Gitleaks-inspired regex ruleset
5. **Custom keyword matching** — organisation-specific terms: project names, internal IDs, confidentiality markers
6. **Structural anomaly heuristics** — entropy, size-vs-text ratio, extension mismatch, embedded macros/OLE objects
7. **False-positive suppression** — technical procurement docs and financial cost sheets are classified and irrelevant NER hits (ORG/LOC fragments) are dropped automatically
8. **Policy decision** — maps scan results to a risk level and decision (ALLOW / ALLOW_WITH_WARNING / BLOCK)
9. **Audit event log** — every scan and decision is appended as an immutable SQLite row
10. **Betriebsrat CSV export** — date-range filtered export for works council / internal audit

No LLMs are used at any point. All processing is local and offline-capable.

---

## Example scenarios

Detailed examples live in separate markdown files:

- [PII examples](docs/examples_pii.md)
- [Secret and credential examples](docs/examples_secrets.md)
- [Keyword and confidentiality examples](docs/examples_keywords.md)
- [Anomaly and suspicious file examples](docs/examples_anomalies.md)
- [Full decision walkthroughs](docs/examples_decision_walkthroughs.md)

These documents show what gets flagged, when warnings are expected, and which document types should be suppressed or reduced.

---

## Expected detections

### PII (via Microsoft Presidio — MIT)

| Entity | Examples | Severity | Languages |
|--------|----------|----------|-----------|
| `EMAIL_ADDRESS` | `max.mustermann@firma.de` | HIGH | EN + DE |
| `PHONE_NUMBER` | `+49 211 1234567` | HIGH | EN + DE |
| `IBAN_CODE` | `DE89 3704 0044 0532 0130 00` | HIGH | EN + DE |
| `CREDIT_CARD` | `4111 1111 1111 1111` | HIGH | EN + DE |
| `PERSON` | `Max Mustermann` | MEDIUM | EN + DE |
| `LOCATION` | Street address, city (suppressed in financial/technical docs) | MEDIUM | EN + DE |
| `ORGANIZATION` | Company names (suppressed in financial/technical docs) | MEDIUM | EN + DE |
| `IP_ADDRESS` | `192.168.1.1` | LOW | EN + DE |
| `DATE_TIME` | Dates in personal context | LOW | EN + DE |

> **False-positive suppression:** Documents classified as financial cost sheets (Kostenkalkulation, Std. Satz, GESAMT-Kosten, etc.) or technical procurement documents (Ausschreibung, Leistungsumfang, DIN EN, etc.) have `ORGANIZATION` and `LOCATION` hits suppressed automatically. NER confidence thresholds are also raised by 0.05 on these document types.

---

### Secrets / Credentials (regex ruleset, Gitleaks-inspired)

| Pattern | Examples | Severity |
|---------|----------|----------|
| AWS Access Key | `AKIA...` | HIGH |
| AWS Secret Key | 40-char base64 after `aws_secret` | HIGH |
| Generic API Key | `api_key = "sk-..."`, `token: "..."` | HIGH |
| JWT | `eyJ...` (header.payload.signature) | HIGH |
| Database URI | `postgresql://user:pass@host/db` | HIGH |
| Private key PEM | `-----BEGIN RSA PRIVATE KEY-----` | HIGH |
| Password in config | `password = "..."`, `passwd:` | MEDIUM |
| Generic secret | `secret = "..."`, `SECRET_KEY = ...` | MEDIUM |

---

### Keywords (configurable YAML lists)

Keyword lists live in `config/keywords/`. Add domain-specific terms per file:

| List | Sample triggers |
|------|----------------|
| `confidentiality.yaml` | Geheimhaltungsvereinbarung, NDA, vertraulich, confidential, internal only |
| `hr.yaml` | Betriebsrat, Personalakte, Gehalt, Lohnabrechnung, Kündigung, Abmahnung |
| `finance.yaml` | Jahresabschluss, Bilanz, Gewinn und Verlust, Steuerprüfung, IBAN, Kontonummer |
| `legal.yaml` | EVB-IT, Vergaberecht, VOB, Rechtsstreit, Klage, Vergleich |

---

### Structural anomalies

| Check | Trigger condition | Severity |
|-------|-------------------|----------|
| Extension mismatch | MIME magic ≠ declared extension (e.g. `.pdf` but binary is EXE) | HIGH |
| High entropy | Shannon entropy > threshold on raw file chunks (likely encrypted/compressed payload) | MEDIUM |
| Size vs text ratio | File size >> extracted text length for the file type (hidden binary content) | MEDIUM |
| Embedded macro | DOCX/XLSX contains VBA macros or OLE objects | MEDIUM |
| Archive bomb | ZIP recursion depth or unpacked size exceeds limits | HIGH |

---

## Policy decisions

| Condition | Risk level | Decision |
|-----------|------------|----------|
| No hits | `CLEAN` | `ALLOW` |
| PII hits ≥ threshold (default: 1) | `SENSITIVE_PII` | `ALLOW_WITH_WARNING` |
| Any secret hit | `SECRET_FOUND` | `ALLOW_WITH_WARNING` |
| Any keyword hit | `SENSITIVE_PII` | `ALLOW_WITH_WARNING` |
| High anomaly (e.g. extension mismatch, entropy spike) | `STRUCTURAL_ANOMALY` | `ALLOW_WITH_WARNING` |
| *(BLOCK path wired, activatable via threshold config)* | any | `BLOCK` |

Thresholds are configurable via `.env` / `config.py`.

---

## Supported file types

| Format | Extractor |
|--------|-----------|
| PDF | `pymupdf` (fitz) |
| DOCX | `python-docx` |
| XLSX | `openpyxl` |
| TXT | built-in |
| RTF | `striprtf` |

---

## Tech stack

| Layer | Choice | License |
|-------|--------|---------|
| API | FastAPI + uvicorn | MIT |
| UI | Streamlit | Apache-2.0 |
| PII detection | [Microsoft Presidio](https://github.com/microsoft/presidio) + spaCy | MIT |
| NLP models | `en_core_web_md`, `de_core_news_md` | MIT / CC-BY-SA-3.0 |
| File type detection | `puremagic` | MIT |
| Secret scanning | Custom regex (Gitleaks-inspired, written from scratch) | MIT |
| Audit storage | SQLite via `aiosqlite` | MIT |
| Language detection | `langdetect` | Apache-2.0 |
| Policy engine | Inline Python (OPA/Rego planned) | — |

---

## Repository structure

```text
compliance-pre-scan/
├── README.md
├── docs/
│   ├── examples_pii.md
│   ├── examples_secrets.md
│   ├── examples_keywords.md
│   ├── examples_anomalies.md
│   └── examples_decision_walkthroughs.md
├── pyproject.toml
├── .env.example
├── debug_scan.py               # CLI: scan a single file, full debug output
│
├── config/
│   └── keywords/
│       ├── confidentiality.yaml
│       ├── hr.yaml
│       └── finance.yaml
│
├── logs/
│   └── compliance_scan.log
│
├── src/
│   └── compliance_scan/
│       ├── __init__.py
│       ├── logging_setup.py
│       ├── config.py
│       ├── pipeline.py
│       ├── extractors/
│       ├── scanners/
│       ├── audit/
│       └── api/
│
├── ui/
│   └── app.py
│
└── tests/
    ├── test_extractors.py
    ├── test_scanners.py
    ├── test_policy.py
    └── fixtures/
```

---

## Quick start

```bash
git clone https://github.com/anbilly19/compliance-pre-scan
cd compliance-pre-scan
uv sync

# start backend
uvicorn compliance_scan.api.app:app --reload

# start UI (separate terminal)
streamlit run ui/app.py

# or scan a single file directly from CLI
uv run python debug_scan.py path/to/file.pdf
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
    filename         TEXT NOT NULL,
    action           TEXT NOT NULL,
    risk_level       TEXT NOT NULL,
    decision         TEXT NOT NULL,
    pii_count        INTEGER DEFAULT 0,
    secret_count     INTEGER DEFAULT 0,
    keyword_count    INTEGER DEFAULT 0,
    anomaly_flags    TEXT DEFAULT '[]',
    scan_duration_ms INTEGER
);
```

Every scan writes one row. Manual breach reports and override events will add additional row types (`MANUAL_BREACH_REPORT`, `MANUAL_OVERRIDE`) in a future sprint.

---

## Betriebsrat CSV export columns

| Column | Notes |
|--------|-------|
| `timestamp` | ISO 8601 |
| `user_id` | Pseudonymised (SHA-256) or real ID for authorised exports |
| `filename` | Stored as-is in current test mode |
| `risk_level` | `CLEAN` / `SENSITIVE_PII` / `SECRET_FOUND` / `STRUCTURAL_ANOMALY` |
| `decision` | `ALLOW` / `ALLOW_WITH_WARNING` / `BLOCK` |
| `pii_count` | integer |
| `secret_count` | integer |
| `keyword_count` | integer |
| `anomaly_flags` | JSON array |
| `scan_duration_ms` | integer |

Raw file content is **never** included in the export.

---

## Planned (next sprints)

- **Manual breach report** — "Datenpanne melden" button in UI creates a `MANUAL_BREACH_REPORT` audit event with free-text reason and severity
- **BLOCK enforcement** — hard-block at chat layer when backend returns `BLOCK`; currently wired but not enforced
- **Hit masking config flag** — `MASK_SNIPPETS=true` for production; currently off for testing
- **ClamAV integration** — optional sidecar for known-malware signature scanning
- **OPA/Rego** — externalise policy rules out of `pipeline.py`

---

## License

MIT — all core dependencies (Presidio, puremagic, FastAPI, aiosqlite, Streamlit) are MIT or Apache-2.0 licensed.  
Gitleaks-inspired secret patterns are written from scratch to avoid GPL contamination.
