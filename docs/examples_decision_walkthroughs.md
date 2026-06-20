# Detection examples — full decision walkthroughs

This document ties together multiple scanners to show how the system behaves end-to-end, including the policy engine decision and audit trail output.

> **BLOCK decisions return HTTP 451.** The full `ScanResult` JSON is included in the response body so the chat layer can show exactly why the upload was rejected.  
> **Hit masking** — when `MASK_SNIPPETS=true` in production, snippets in the response and audit log are partially redacted before writing.

---

## Scenario 1 — CV uploaded into chat

**File:** `anna_schmidt_cv.pdf`

**Contains:** name, email, phone number, address, date of birth

**Policy engine input:**
```
pii_count=5, secret_count=0, keyword_count=0, high_anomaly_count=0
```

**Expected result:**
- PII scanner raises multiple hits (PERSON, EMAIL_ADDRESS, PHONE_NUMBER, LOCATION)
- No secret or anomaly hits
- Policy: `risk_level=SENSITIVE_PII`, `decision=ALLOW_WITH_WARNING`, `reason=pii_warn`
- **HTTP 200** — upload proceeds with warning banner shown to user
- Audit event written: `action=PRE_SCAN_COMPLETED`, `pii_count=5`, `decision=ALLOW_WITH_WARNING`
- With `MASK_SNIPPETS=true`: email snippet becomes `an***de`, person name kept as-is (KEYWORD pass-through)

---

## Scenario 2 — `.env` file with credentials

**File:** `.env.txt`

**Contains:** API key, DB connection string, JWT token

**Policy engine input:**
```
pii_count=0, secret_count=3, keyword_count=0, high_anomaly_count=0
```

**Expected result:**
- Secret scanner raises 3 HIGH hits
- Policy: `risk_level=SECRET_FOUND`, `decision=BLOCK`, `reason=block_on_secret`
- **HTTP 451** — file never reaches LLM
- Audit event written: `action=PRE_SCAN_COMPLETED`, `secret_count=3`, `decision=BLOCK`
- With `MASK_SNIPPETS=true`: AWS key snippet `AKIA...` → `AKIA****`, DB URI password stripped to `post****`

> Default: `BLOCK_ON_SECRET=1`. Any single secret hit blocks the upload.

---

## Scenario 3 — Internal Betriebsrat memo

**File:** `betriebsrat_notizen.docx`

**Contains:** labour council terms, employee names, disciplinary wording

**Policy engine input:**
```
pii_count=3, secret_count=0, keyword_count=4, high_anomaly_count=0
```

**Expected result:**
- Keyword scanner flags: Betriebsrat, Personalakte, Kündigung, Abmahnung
- PII scanner flags employee names
- Policy: `risk_level=SENSITIVE_PII`, `decision=ALLOW_WITH_WARNING`, `reason=pii_warn`
- **HTTP 200** — warning banner shown; both scanner results written to audit trail
- Keywords pass through masking unchanged (`Betriebsrat` → `Betriebsrat`)

---

## Scenario 4 — Cost sheet with company/location noise

**File:** `KB_263104_089.xlsx`

**Contains:** company abbreviations, city names, rates and totals — no real employee/customer PII

**Policy engine input (after suppression):**
```
pii_count=0, secret_count=0, keyword_count=0, high_anomaly_count=0
```

**Expected result:**
- Finance classifier marks document as financial cost sheet
- ORG and LOCATION NER hits suppressed automatically (see [false_positive_suppression.md](false_positive_suppression.md))
- Policy: `risk_level=CLEAN`, `decision=ALLOW`, `reason=clean`
- **HTTP 200** — no warning shown

---

## Scenario 5 — Fake PDF with embedded payload

**File:** `invoice.pdf` (magic bytes identify a Windows executable)

**Policy engine input:**
```
pii_count=0, secret_count=0, keyword_count=0, high_anomaly_count=1
```

**Expected result:**
- File identity mismatch: declared `application/pdf`, detected `application/x-dosexec`
- Anomaly scanner raises HIGH hit: `extension_mismatch`
- With `BLOCK_ON_STRUCTURAL_ANOMALY=true` (default):
  - Policy: `risk_level=STRUCTURAL_ANOMALY`, `decision=BLOCK`, `reason=block_on_structural_anomaly`
  - **HTTP 451**
- With `BLOCK_ON_STRUCTURAL_ANOMALY=false`:
  - Policy: `decision=ALLOW_WITH_WARNING`, `reason=high_anomaly`
  - **HTTP 200** with warning

---

## Scenario 6 — Technical tender document

**File:** `anfrage-seitenrolle.pdf`

**Contains:** DIN references, supplier names, city/project references, technical scope language

**Policy engine input (after suppression):**
```
pii_count=0, secret_count=0, keyword_count=0, high_anomaly_count=0
```

**Expected result:**
- Technical classifier activates (Ausschreibung, Leistungsumfang, DIN EN keywords detected)
- Noisy ORG/LOCATION hits suppressed
- Only real sensitive signals remain (none in this case)
- Policy: `risk_level=CLEAN`, `decision=ALLOW`, `reason=clean`
- **HTTP 200** — no warning

---

## Policy engine and OPA

All scenarios above use the same policy logic whether the inline Python fallback or OPA/Rego is active. The `reason` field in the result identifies which rule fired:

| reason | Meaning |
|--------|---------|
| `clean` | No hits |
| `pii_warn` | PII count ≥ `PII_WARN_THRESHOLD` |
| `block_on_pii` | PII count ≥ `BLOCK_ON_PII` |
| `secret_warn` | Secret count ≥ `SECRET_WARN_THRESHOLD` |
| `block_on_secret` | Secret count ≥ `BLOCK_ON_SECRET` |
| `keyword_match` | At least one keyword hit |
| `high_anomaly` | HIGH anomaly, blocking disabled |
| `block_on_structural_anomaly` | HIGH anomaly, blocking enabled |

---

## Operational note

These examples are for business discussion, tuning, and UAT. They help explain to compliance, security, and Betriebsrat stakeholders why the scanner warned or blocked, what it detected, what was masked, and where suppression was applied.
