# Detection examples — full decision walkthroughs

This document ties together multiple scanners to show how the system behaves end-to-end.

---

## Scenario 1 — CV uploaded into chat

**File**

- `anna_schmidt_cv.pdf`

**Contains**

- name
- email
- phone number
- address
- date of birth

**Expected result**

- PII scanner raises multiple hits
- no secret hits
- no anomaly hits
- final result: `risk_level = SENSITIVE_PII`, `decision = ALLOW_WITH_WARNING`

---

## Scenario 2 — `.env` file with credentials

**File**

- `.env.txt`

**Contains**

- API key
- DB connection string
- JWT token

**Expected result**

- secret scanner raises several HIGH hits
- final result: `risk_level = SECRET_FOUND`, `decision = ALLOW_WITH_WARNING`

---

## Scenario 3 — Internal Betriebsrat memo

**File**

- `betriebsrat_notizen.docx`

**Contains**

- labour council terms
- employee names
- disciplinary wording

**Expected result**

- keyword scanner flags labour-council terms
- PII scanner flags names
- final result: warning with audit trail entries from both scanners

---

## Scenario 4 — Cost sheet with company/location noise

**File**

- `KB_263104_089.xlsx`

**Contains**

- company abbreviations
- city names
- rates and totals
- no real employee/customer PII

**Expected result**

- finance classifier marks document as financial
- ORG and LOCATION NER hits are suppressed
- final result should be clean or much quieter than before

---

## Scenario 5 — Fake PDF with embedded payload

**File**

- `invoice.pdf`

**Reality**

- extension says PDF
- magic bytes identify another binary type

**Expected result**

- file identity mismatch
- anomaly hit raised
- final result: `STRUCTURAL_ANOMALY`

---

## Scenario 6 — Technical tender document

**File**

- `anfrage-seitenrolle.pdf`

**Contains**

- DIN references
- supplier names
- city/project references
- technical scope language

**Expected result**

- technical classifier activates
- noisy ORG/LOCATION hits reduced heavily
- only real sensitive signals should remain

---

## Operational note

These examples are meant for business discussion, tuning, and UAT. They also help explain to compliance, security, and Betriebsrat stakeholders why the scanner warned, what it detected, and where suppression is intentionally applied.
