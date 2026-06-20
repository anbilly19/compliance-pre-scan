# False-positive suppression

The compliance scanner applies suppression logic to reduce noise from documents where certain PII entity types are structurally expected and not indicative of a data protection risk.

Suppression only affects which hits are surfaced in the final `ScanResult` and audit log. The underlying scan still runs in full. Suppression decisions are themselves recorded so the audit trail remains transparent.

---

## What gets suppressed and when

### Suppressed entity types

| Entity type | Suppressed in |
|-------------|---------------|
| `ORGANIZATION` | Financial cost sheets + technical procurement docs |
| `LOCATION` | Financial cost sheets + technical procurement docs |

No other entity types are suppressed. The following are **never** suppressed regardless of document type:

- `EMAIL_ADDRESS`
- `PHONE_NUMBER`
- `IBAN_CODE`
- `CREDIT_CARD`
- `PERSON` (names are not suppressed; only ORG/LOC)
- Any secret hit
- Any anomaly hit

---

## Classifier: financial cost sheet

A document is classified as a financial cost sheet when it contains a configurable number of these signals:

| Signal | Example |
|--------|---------|
| Cost/rate headers | `Std. Satz`, `T/M Satz`, `GESAMT-Kosten` |
| German cost terms | `Kostenkalkulation`, `Tagessatz`, `Gesamtkosten` |
| Currency patterns | `€`, `EUR`, `1.234,56` |
| Column-like numerics | Multiple decimal numbers in tabular layout |

**Confidence threshold:** 0.6 (default). Documents below this threshold are not classified and receive no suppression.

---

## Classifier: technical procurement document

A document is classified as a technical procurement document when it contains signals such as:

| Signal | Example |
|--------|---------|
| Procurement terms | `Ausschreibung`, `Leistungsumfang`, `Anforderung` |
| Standards references | `DIN EN`, `ISO`, `VDE`, `CE-Kennzeichnung` |
| Delivery/scope terms | `Lieferumfang`, `Pflichtenheft`, `Lastenheft` |
| Contract framework | `EVB-IT`, `VOB`, `Rahmenvertrag` |

**Confidence threshold:** 0.6 (default). Same logic as financial classifier.

---

## NER confidence threshold adjustment

On classified documents, the minimum confidence threshold for NER hits is raised by **+0.05** (e.g. from 0.80 to 0.85). This reduces borderline ORG/LOC matches that spaCy detects in abbreviations and product names.

---

## Audit transparency

Suppression decisions are recorded in the audit trail:

- `suppressed_count`: number of hits removed by suppression
- `suppression_reason`: classifier name that triggered suppression (e.g. `financial_cost_sheet`)
- Suppressed hits are not included in `pii_count` or the hit lists returned by the API

This means a Betriebsrat export will correctly show `pii_count=0` for a cost sheet, and also include the suppression reason so the decision is auditable.

---

## What is never suppressed

- Any HIGH-severity PII entity (`EMAIL_ADDRESS`, `PHONE_NUMBER`, `IBAN_CODE`, `CREDIT_CARD`)
- Any secret scanner hit
- Any anomaly scanner hit
- `PERSON` entities (names are not suppressed; only company/location labels)
- Documents below the classifier confidence threshold

---

## Interaction with BLOCK decisions

Suppression runs **before** the policy engine receives hit counts. This means:

- A cost sheet with suppressed ORG/LOC hits but no unsuppressed PII → `pii_count=0` → `CLEAN` / `ALLOW`
- A cost sheet that also contains an IBAN → suppression does not remove the IBAN → `pii_count=1` → `ALLOW_WITH_WARNING` or `BLOCK` depending on thresholds

---

## Interaction with hit masking

Masking (Phase 11) runs **after** suppression and **after** the policy decision. The sequence is:

1. Scan all entities
2. Suppress per classifier
3. Policy engine evaluates surviving hits
4. Masking applied to snippets in surviving hits
5. Masked result written to audit DB and returned by API

---

## Tuning

- Raise classifier confidence thresholds if suppression is too aggressive for your document mix
- Add signals to the classifier keyword lists in `src/compliance_scan/scanners/false_positive_suppressor.py`
- Monitor `suppressed_count` in the audit log; a consistently high value may indicate the classifier is over-firing
- Do not suppress `PERSON` — employee names in financial documents are still a data protection consideration
