# False positives — what gets suppressed and why

This document explains which detections the system deliberately reduces or removes, what logic makes that decision, and what the business rationale is.

The goal is to give compliance officers, Betriebsrat representatives, and developers a transparent view of where the scanner is intentionally lenient — and why.

---

## Why suppression is necessary

PII and NER models are trained on general text. In a business context, many strings look like personal data but are actually:

- company abbreviations acting as client codes (`SMGB`, `BWW`, `MRM`)
- city names appearing in addresses of the business, not a private person
- role titles or column headers that NER misreads as person names
- standards references (`DIN EN 1090`, `ISO 9001`) that look like names or locations
- measurement units and part codes that accidentally match regex patterns

Without suppression, every procurement document, cost sheet, and technical spec triggers a wall of medium-severity warnings — making the tool useless because users start ignoring all warnings.

Signal quality matters more than raw hit count.

---

## Document type classifiers

Before suppression is applied, the pipeline attempts to classify the document by scanning the extracted text for known structural signals.

### Financial / cost-sheet classifier

Triggers on ≥ 3 of the following signals:

| Signal | Example |
|--------|---------|
| `Kostenerfassung` | header of internal cost sheets |
| `Kostenkalkulation` | cost calculation title |
| `Std. Satz` | hourly rate column label |
| `GESAMT-Kosten` | total cost row |
| `Abgerechnet` | billed amount row |
| `Differenzbetrag` | difference/variance row |
| `GMK` | overhead rate abbreviation |
| `Reisekosten` | travel expenses |
| `Hotelkosten` | hotel expenses |
| `Mietwagenkosten` | car rental |
| `Flugkosten` | flight costs |
| `Kundenbetreuung` | client service cost line |

**Effect:** `ORGANIZATION` and `LOCATION` entity hits are suppressed entirely. These entities add no compliance signal in a cost sheet — they are company codes and work locations, not personal data.

---

### Technical procurement document classifier

Triggers on ≥ 4 of the following signals:

| Signal | Example |
|--------|---------|
| `Auftragnehmer` | contractor |
| `Leistungsumfang` | scope of services |
| `Ausschreibung` | tender |
| `Anfrage` | inquiry |
| `Angebot` | offer/quote |
| `Lieferumfang` | delivery scope |
| `Montage` | assembly |
| `Inbetriebnahme` | commissioning |
| `DIN EN` | standards reference |
| `Auftraggeber` | client/principal |
| `Leistungsverzeichnis` | schedule of services |
| `Vergabe` | award/procurement |

**Effect:** `ORGANIZATION` and `LOCATION` hits are suppressed. NER confidence threshold is raised by 0.05 for all entities. Company and city names in tender documents are structural noise.

---

## Global suppression rules (all document types)

These patterns are checked against the matched text string regardless of document type. A match removes the hit.

| Pattern type | Examples suppressed | Reason |
|---|---|---|
| Standards references | `DIN EN 1090`, `ISO 9001-2`, `VDE 0100` | Look like names/locations but are norms |
| Legal/regulatory abbreviations | `BGB`, `VOB`, `HOAI`, `BetrSichV`, `GefStoffV` | German law codes, not entities |
| EU/regulatory prefixes | `CE`, `EG`, `EWG`, `RL` | Regulatory markers |
| Measurement values | `25 mm`, `4.5 kN`, `120 °C`, `85%` | Numeric + unit combos |
| Short date strings | `12.03.2026` | Date-only strings with no personal context |
| Execution class labels | `EXC II`, `EXC 3` | Steel construction class designations |
| RAL colour codes | `RAL 7016` | Colour standard codes |
| Version strings | `v1.4.2`, `3.0.1` | Software/document version numbers |
| Legal entity suffixes alone | `GmbH`, `AG`, `KG`, `OHG` | Suffix without a real company name |
| Major German cities (standalone) | `Berlin`, `München`, `Frankfurt`, `Essen` | City-only strings without address context |
| All-uppercase short tokens | `BW`, `MR`, `RM`, `KP` | Column headers, initials, codes |
| Pure numeric strings | `12345`, `0.00`, `100` | Numbers that triggered NER |

---

## Financial document-specific suppression

Applied when the financial classifier fires, on top of global rules.

| Pattern type | Examples suppressed | Reason |
|---|---|---|
| Short client codes (2–6 uppercase) | `SMGB`, `BWW`, `MRM`, `KP2K` | Client abbreviations in cost table headers |
| NRW industrial city names | `Mülheim`, `Duisburg`, `Oberhausen`, `Gelsenkirchen` | Work location references |
| Company-specific headers | `SIKOTEC`, `KOSTENERFASSUNG`, `ORIGINAL`, `MUSTER` | Sheet or company header text |
| Role/column abbreviations | `Ing`, `Techn`, `Kaufm`, `OM`, `RM` | Column labels for staff categories |
| Form keywords | `Kunde`, `Objekt`, `Firma`, `Auftrags`, `Angebots` | Field label text in forms |

---

## Technical document-specific suppression

Applied when the technical classifier fires, on top of global rules.

| Pattern type | Examples suppressed | Reason |
|---|---|---|
| Role terms | `Auftraggeber`, `Auftragnehmer`, `Bauleiter`, `Projektleiter` | Roles, not names |
| Process terms | `Montage`, `Inbetriebnahme`, `Demontage`, `Abnahme` | Process steps, not entities |
| Document type terms | `Anfrage`, `Angebot`, `Lastenheft`, `Pflichtenheft` | Document category labels |
| Known industrial brands | `Siemens`, `ABB`, `Bosch`, `Beckhoff`, `SEW` | Component vendor names common in tech specs |
| Material/grade codes | `P91`, `X80`, `L555`, `SA 2.5` | Steel and material grade codes |

---

## Score-based filtering

Before pattern suppression, every Presidio hit must pass a minimum confidence score:

| Entity category | Minimum score (normal) | Minimum score (technical/financial doc) |
|-----------------|------------------------|------------------------------------------|
| Regex entities (EMAIL, IBAN, PHONE, CREDIT_CARD, IP) | 0.60 | 0.65 |
| NER entities (PERSON, LOCATION, ORGANIZATION) | 0.85 | 0.90 |

Hits below these thresholds are dropped before pattern matching and never reach the audit trail.

---

## What suppression does NOT remove

These are never suppressed regardless of document type or score:

- `EMAIL_ADDRESS` with valid domain
- `IBAN_CODE` matching a valid checksum structure
- `CREDIT_CARD` matching Luhn algorithm
- `PHONE_NUMBER` matching a structured German or international format
- Any secret scanner hit (API keys, tokens, PEM keys, DB URIs)
- Any keyword scanner hit (these are always intentional business rules)
- Any anomaly hit (file structure issues are always surfaced)

---

## Audit transparency

Every dropped hit is logged at `DEBUG` level in `logs/compliance_scan.log` with:

- the entity type
- the raw matched text
- the confidence score
- the suppression reason (`SCORE-DROP` or `FP-SUPPRESSED`)

This means suppression decisions are auditable. If a stakeholder questions why a detection disappeared, the log shows exactly what was found and why it was removed.

---

## Tuning guidance

| Situation | What to do |
|-----------|------------|
| Real names in cost sheets are being suppressed | These sheets have personal data — add a specific PERSON check that is not gated by the financial doc classifier |
| A standard like `DIN EN 1090-2` is getting flagged despite suppression | Check if the regex is matching a sub-string; tighten the standard reference pattern |
| A company name is always noisy in procurement docs | Add it to `_TECHNICAL_SUPPRESSION` in `false_positive_filter.py` |
| A city name should be flagged because it is part of a personal address | Consider context window — a street + number + city combination should override suppression in future |
| New client abbreviations appear in cost sheets | Add them as new patterns in `_FINANCIAL_SUPPRESSION` or widen the short-code regex |
