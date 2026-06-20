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
| 9 | Manual breach report UI + `POST /compliance/breach-report` | ✅ Done |
| 10 | BLOCK enforcement — HTTP 451, config flags, wired pipeline, tests | ✅ Done |
| 11 | Hit masking — `MASK_SNIPPETS` flag, `masking.py`, applied in pipeline, tests | ✅ Done |
| 12 | OPA/Rego policy externalisation — `policy/engine.py`, `compliance.rego`, inline fallback, tests | ✅ Done |

---

## What this does

When a user selects a file for upload in the chat platform, this service intercepts it **before** it reaches the LLM agent and runs a multi-layer scan:

1. **File identity check** — validates MIME type vs. declared extension (catches disguised payloads)
2. **Text extraction** — pulls raw text from PDF, DOCX, XLSX, TXT, RTF
3. **PII detection** — finds personal identifiers using Microsoft Presidio with bilingual EN + DE NER and regex recognisers
4. **Secret / credential scanning** — detects API keys, tokens, DB connection strings, passwords
5. **Custom keyword matching** — organisation-specific terms: project names, internal IDs, confidentiality markers
6. **Structural anomaly heuristics** — entropy, size-vs-text ratio, extension mismatch, embedded macros/OLE objects
7. **False-positive suppression** — technical procurement docs and financial cost sheets suppress irrelevant NER hits automatically
8. **Policy decision** — maps scan results to a risk level and decision via OPA/Rego or inline Python fallback
9. **Hit masking** — when `MASK_SNIPPETS=true`, sensitive snippets are masked before DB write and API response
10. **Audit event log** — every scan and manual breach report is appended as an immutable SQLite row
11. **Betriebsrat CSV export** — date-range filtered export for works council / internal audit

No LLMs are used at any point. All processing is local and offline-capable.

---

## Example scenarios and detection reference

| Document | What it covers |
|----------|---------------|
| [PII examples](docs/examples_pii.md) | What personal data triggers warnings; which document types reduce noise |
| [Secret and credential examples](docs/examples_secrets.md) | API keys, DB URIs, JWTs, PEM keys; placeholder tuning notes |
| [Keyword and confidentiality examples](docs/examples_keywords.md) | Betriebsrat, HR, finance, legal keyword triggers |
| [Anomaly and suspicious file examples](docs/examples_anomalies.md) | Extension mismatch, macros, entropy, size ratio, archive bombs |
| [Full decision walkthroughs](docs/examples_decision_walkthroughs.md) | End-to-end scenarios tying multiple scanners together |
| [False-positive suppression explained](docs/false_positive_suppression.md) | What gets suppressed, confidence thresholds, tuning guidance |

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

### Structural anomalies

| Check | Trigger condition | Severity |
|-------|-------------------|----------|
| Extension mismatch | MIME magic ≠ declared extension | HIGH |
| High entropy | Shannon entropy > threshold (likely encrypted/compressed payload) | MEDIUM |
| Size vs text ratio | File size >> extracted text length (hidden binary content) | MEDIUM |
| Embedded macro | DOCX/XLSX contains VBA macros or OLE objects | MEDIUM |
| Archive bomb | ZIP recursion depth or unpacked size exceeds limits | HIGH |

---

## Hit masking

Controlled by `MASK_SNIPPETS` in `.env` (default: `false`).

| Scanner | Masking rule | Example |
|---------|-------------|----------|
| `PII` | Keep first 2 + last 2 chars | `max.mustermann@firma.de` → `ma***de` |
| `SECRET` | Keep first 4 chars only | `AKIAIOSFODNN7EXAMPLE` → `AKIA****` |
| `KEYWORD` | Pass through unchanged | `CONFIDENTIAL` → `CONFIDENTIAL` |
| `ANOMALY` | Pass through unchanged | `extension_mismatch: pdf vs exe` → unchanged |

Set `MASK_SNIPPETS=true` in production. Masking is applied before DB write and API response.

---

## Policy engine (OPA / Rego)

Policy logic lives in `config/policy/compliance.rego` and is evaluated by the `policy/engine.py` module.

**Two modes — same behaviour:**

| Mode | When active | How to switch |
|------|-------------|---------------|
| Inline Python fallback | `OPA_URL` not set (default) | No setup needed |
| OPA / Rego | `OPA_URL=http://localhost:8181` | Run OPA server pointing at `config/policy/` |

The inline fallback is an exact Python mirror of the Rego rules, so you can develop and test without OPA installed. Set `OPA_URL` in production to decouple policy changes from deployments.

**Run OPA locally:**

```bash
# single binary, Apache-2.0 licensed
opa run --server config/policy/

# then in .env:
OPA_URL=http://localhost:8181
```

**Policy priority: BLOCK > ALLOW\_WITH\_WARNING > ALLOW**

| Condition | Risk level | Decision | HTTP |
|-----------|------------|----------|------|
| No hits | `CLEAN` | `ALLOW` | 200 |
| PII hits ≥ `PII_WARN_THRESHOLD` | `SENSITIVE_PII` | `ALLOW_WITH_WARNING` | 200 |
| PII hits ≥ `BLOCK_ON_PII` (if > 0) | `SENSITIVE_PII` | `BLOCK` | **451** |
| Secret hits ≥ `SECRET_WARN_THRESHOLD` | `SECRET_FOUND` | `ALLOW_WITH_WARNING` | 200 |
| Secret hits ≥ `BLOCK_ON_SECRET` (default: 1) | `SECRET_FOUND` | `BLOCK` | **451** |
| Any keyword hit | `SENSITIVE_PII` | `ALLOW_WITH_WARNING` | 200 |
| HIGH anomaly | `STRUCTURAL_ANOMALY` | `ALLOW_WITH_WARNING` | 200 |
| HIGH anomaly + `BLOCK_ON_STRUCTURAL_ANOMALY=true` | `STRUCTURAL_ANOMALY` | `BLOCK` | **451** |

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
| Policy engine | Inline Python + optional [OPA](https://www.openpolicyagent.org/) / Rego | Apache-2.0 |

---

## Repository structure

```text
compliance-pre-scan/
├── README.md
├── docs/
├── pyproject.toml
├── .env.example
├── debug_scan.py
├── config/
│   ├── keywords/
│   └── policy/
│       └── compliance.rego     ← Phase 12
└── src/compliance_scan/
    ├── config.py
    ├── pipeline.py
    ├── masking.py              ← Phase 11
    ├── policy/                 ← Phase 12
    │   ├── __init__.py
    │   └── engine.py
    ├── extractors/
    ├── scanners/
    ├── audit/
    └── api/

tests/
├── test_extractors.py
├── test_scanners.py
├── test_block_enforcement.py
├── test_masking.py
├── test_policy_engine.py       ← Phase 12
└── fixtures/
```

---

## Quick start

```bash
git clone https://github.com/anbilly19/compliance-pre-scan
cd compliance-pre-scan
uv sync
uvicorn compliance_scan.api.app:app --reload
streamlit run ui/app.py
```

---

## Integrating BLOCK into your chat layer

```python
resp = requests.post(
    "http://compliance-scan/scan",
    data={"user_id": user_id, "session_id": session_id},
    files={"file": (filename, file_bytes, mime_type)},
)

if resp.status_code == 451:
    result = resp.json()
    raise UploadBlockedError(risk=result["risk_level"], hits=result["secret_matches"])

if resp.status_code == 200 and resp.json()["decision"] == "ALLOW_WITH_WARNING":
    show_warning_banner(resp.json())

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
    action           TEXT NOT NULL,
    risk_level       TEXT NOT NULL,
    decision         TEXT NOT NULL,
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

## License

MIT — all core dependencies (Presidio, puremagic, FastAPI, aiosqlite, Streamlit) are MIT or Apache-2.0 licensed.  
Gitleaks-inspired secret patterns are written from scratch to avoid GPL contamination.
