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
| 9 | Manual breach report UI + `POST /compliance/breach-report` | ✅ Done |
| 10 | BLOCK enforcement — HTTP 451, config flags, wired pipeline, tests | ✅ Done |
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
8. **Policy decision** — maps scan results to a risk level and decision (`ALLOW` / `ALLOW_WITH_WARNING` / `BLOCK`)
9. **Audit event log** — every scan and manual breach report is appended as an immutable SQLite row
10. **Betriebsrat CSV export** — date-range filtered export for works council / internal audit

No LLMs are used at any point. All processing is local and offline-capable.

---

## Example scenarios and detection reference

Detailed examples and suppression logic live in the `docs/` folder:

| Document | What it covers |
|----------|---------------|
| [PII examples](docs/examples_pii.md) | What personal data triggers warnings; which document types reduce noise |
| [Secret and credential examples](docs/examples_secrets.md) | API keys, DB URIs, JWTs, PEM keys; placeholder tuning notes |
| [Keyword and confidentiality examples](docs/examples_keywords.md) | Betriebsrat, HR, finance, legal keyword triggers; tuning weak signals |
| [Anomaly and suspicious file examples](docs/examples_anomalies.md) | Extension mismatch, macros, entropy, size ratio, archive bombs |
| [Full decision walkthroughs](docs/examples_decision_walkthroughs.md) | End-to-end scenarios tying multiple scanners together |
| [False-positive suppression explained](docs/false_positive_suppression.md) | What gets suppressed, which classifiers trigger suppression, confidence thresholds, what is never suppressed, audit transparency, tuning guidance |

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

> **False-positive suppression:** Documents classified as financial cost sheets (Kostenkalkulation, Std. Satz, GESAMT-Kosten, etc.) or technical procurement documents (Ausschreibung, Leistungsumfang, DIN EN, etc.) have `ORGANIZATION` and `LOCATION` hits suppressed automatically. NER confidence thresholds are also raised by 0.05 on these document types. See [false_positive_suppression.md](docs/false_positive_suppression.md) for full details.

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

| Condition | Risk level | Decision | HTTP |
|-----------|------------|----------|------|
| No hits | `CLEAN` | `ALLOW` | 200 |
| PII hits ≥ `PII_WARN_THRESHOLD` | `SENSITIVE_PII` | `ALLOW_WITH_WARNING` | 200 |
| PII hits ≥ `BLOCK_ON_PII` (if > 0) | `SENSITIVE_PII` | `BLOCK` | **451** |
| Any secret hit ≥ `SECRET_WARN_THRESHOLD` | `SECRET_FOUND` | `ALLOW_WITH_WARNING` | 200 |
| Secret hits ≥ `BLOCK_ON_SECRET` (default: 1) | `SECRET_FOUND` | `BLOCK` | **451** |
| Any keyword hit | `SENSITIVE_PII` | `ALLOW_WITH_WARNING` | 200 |
| HIGH anomaly (ext mismatch, entropy spike) | `STRUCTURAL_ANOMALY` | `ALLOW_WITH_WARNING` | 200 |
| HIGH anomaly + `BLOCK_ON_STRUCTURAL_ANOMALY=true` | `STRUCTURAL_ANOMALY` | `BLOCK` | **451** |

All thresholds are configurable via `.env`. See `.env.example` for the full list.

> **HTTP 451** is returned for all `BLOCK` decisions. The full `ScanResult` JSON is included in the response body so the upstream chat layer can display exactly why the upload was blocked.

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
│   ├── examples_decision_walkthroughs.md
│   └── false_positive_suppression.md
├── pyproject.toml
├── .env.example
├── debug_scan.py
│
├── config/
│   └── keywords/
│       ├── confidentiality.yaml
│       ├── hr.yaml
│       └── finance.yaml
│
├── src/
│   └── compliance_scan/
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
    ├── test_block_enforcement.py
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

# scan a single file from CLI
uv run python debug_scan.py path/to/file.pdf
```

---

## Integrating BLOCK into your chat layer

The scan endpoint returns **HTTP 451** for any `BLOCK` decision. Check the status code before forwarding the file to the LLM:

```python
resp = requests.post(
    "http://compliance-scan/scan",
    data={"user_id": user_id, "session_id": session_id},
    files={"file": (filename, file_bytes, mime_type)},
)

if resp.status_code == 451:
    result = resp.json()
    raise UploadBlockedError(
        risk=result["risk_level"],
        decision=result["decision"],
        hits=result["secret_matches"] + result["anomaly_matches"],
    )

if resp.status_code == 200 and resp.json()["decision"] == "ALLOW_WITH_WARNING":
    show_warning_banner(resp.json())   # display to user, let them confirm

# only reach here if ALLOW or user confirmed WARNING
forward_to_llm(file_bytes)
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
    action           TEXT NOT NULL,          -- PRE_SCAN_COMPLETED | MANUAL_BREACH_REPORT
    risk_level       TEXT NOT NULL,
    decision         TEXT NOT NULL,          -- ALLOW | ALLOW_WITH_WARNING | BLOCK
    pii_count        INTEGER DEFAULT 0,
    secret_count     INTEGER DEFAULT 0,
    keyword_count    INTEGER DEFAULT 0,
    anomaly_flags    TEXT DEFAULT '[]',
    scan_duration_ms INTEGER,
    breach_reason    TEXT,
    breach_severity  TEXT,
    breach_reporter  TEXT
);
```

---

## API endpoints

| Method | Path | Status | Description |
|--------|------|--------|-------------|
| `POST` | `/scan` | 200 / 451 / 415 | Pre-upload scan; **451 = BLOCK** |
| `GET` | `/compliance/events` | 200 | List audit events |
| `GET` | `/compliance/events/export` | 200 | Betriebsrat CSV download |
| `POST` | `/compliance/breach-report` | 201 | Manual breach report |

---

## Betriebsrat CSV export columns

| Column | Notes |
|--------|-------|
| `timestamp` | ISO 8601 |
| `user_id` | Pseudonymised (SHA-256) or real ID |
| `filename` | Stored as-is |
| `action` | `PRE_SCAN_COMPLETED` or `MANUAL_BREACH_REPORT` |
| `risk_level` | `CLEAN` / `SENSITIVE_PII` / `SECRET_FOUND` / `STRUCTURAL_ANOMALY` |
| `decision` | `ALLOW` / `ALLOW_WITH_WARNING` / `BLOCK` |
| `pii_count` | integer |
| `secret_count` | integer |
| `keyword_count` | integer |
| `anomaly_flags` | JSON array |
| `scan_duration_ms` | integer |
| `breach_reason` | free-text (manual reports only) |
| `breach_severity` | LOW / MEDIUM / HIGH / CRITICAL |
| `breach_reporter` | name or role |

Raw file content is **never** included.

---

## Planned (next sprints)

- **Phase 11 — Hit masking** — `MASK_SNIPPETS=true` env flag for production; snippets currently unmasked for dev/test
- **Phase 12 — OPA/Rego** — externalise policy rules out of `pipeline.py` so rules can change without a code deploy
- **ClamAV sidecar** — optional clamd integration for known-malware signature scanning on raw bytes

---

## License

MIT — all core dependencies (Presidio, puremagic, FastAPI, aiosqlite, Streamlit) are MIT or Apache-2.0 licensed.  
Gitleaks-inspired secret patterns are written from scratch to avoid GPL contamination.
