# Detection examples — PII

This document shows concrete examples of files that should raise PII-related concerns during the pre-upload scan.

The system raises a PII concern when extracted text contains personal identifiers such as names, email addresses, phone numbers, IBANs, card numbers, or addresses. In the current implementation, any PII hit at or above threshold leads to `risk_level = SENSITIVE_PII` and `decision = ALLOW_WITH_WARNING`.

---

## Typical cases that should be flagged

### 1. CV / resume

**Example content**

```text
Max Mustermann
max.mustermann@firma.de
+49 171 1234567
Musterstraße 12, 40213 Düsseldorf
Geboren am 12.03.1992
```

**Expected flags**

- `PERSON` → `Max Mustermann`
- `EMAIL_ADDRESS` → `max.mustermann@firma.de`
- `PHONE_NUMBER` → `+49 171 1234567`
- `LOCATION` → `Musterstraße 12, 40213 Düsseldorf`
- `DATE_TIME` → `12.03.1992`

**Expected outcome**

- Risk level: `SENSITIVE_PII`
- Decision: `ALLOW_WITH_WARNING`
- Audit: one event row with `pii_count > 0`

---

### 2. HR letter

**Example content**

```text
Betreff: Abmahnung
Mitarbeiterin: Anna Schmidt
Personalnummer: 4711
Wohnort: Essen
Telefon: 0201 123456
```

**Expected flags**

- `PERSON`
- `PHONE_NUMBER`
- possibly `LOCATION`
- keyword hits from HR list such as `Abmahnung`

**Expected outcome**

- Risk level: `SENSITIVE_PII`
- Decision: `ALLOW_WITH_WARNING`
- Reason: personal employee data in HR context

---

### 3. Customer communication with banking data

**Example content**

```text
Bitte erstatten Sie den Betrag auf folgendes Konto:
IBAN: DE89 3704 0044 0532 0130 00
Kontoinhaber: Maria Keller
```

**Expected flags**

- `IBAN_CODE`
- `PERSON`
- optional finance keywords depending on configured lists

**Expected outcome**

- Risk level: `SENSITIVE_PII`
- Decision: `ALLOW_WITH_WARNING`

---

## Cases that should NOT be escalated as real PII

### 1. Technical procurement documents

**Example content**

```text
Ausschreibung gemäß DIN EN 1090
Leistungsumfang: Montage und Inbetriebnahme
Siemens Schaltschrank
Projektstandort: Essen
```

**Why this should not flood the UI**

- `ORGANIZATION` and `LOCATION` may be detected by NER
- the document classifier marks this as technical
- technical suppression removes low-value ORG/LOC noise

**Expected outcome**

- Remaining PII hits should be reduced strongly
- No warning unless other real PII exists

---

### 2. Financial cost sheets with company/location fragments

**Example content**

```text
Kostenerfassung
Kunde: SMGB Mülheim / BWW
Std. Satz 44.00
GESAMT-Kosten in EUR
```

**Why this should not flood the UI**

- finance classifier detects this as cost-sheet content
- `ORGANIZATION` and `LOCATION` hits are suppressed entirely
- short client codes like `SMGB`, `BWW`, `MRM` are treated as noise in this context

**Expected outcome**

- ideally zero PII hits unless actual personal data is present

---

## Operational note

PII hits are currently shown unmasked in test mode so tuning is easier. In production, masking should be re-enabled via config so the audit trail and UI expose only redacted snippets.
