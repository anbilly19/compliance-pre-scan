# Detection examples — keywords and confidentiality

This document shows examples of organisation-specific keyword matches that should raise concerns even when no structured PII or secret is present.

Keywords are useful for catching sensitive business content such as labour-council material, legal drafts, internal-only project notes, or financial planning documents.

---

## Typical cases that should be flagged

### 1. Labour council / Betriebsrat material

**Example content**

```text
Vorlage für den Betriebsrat
Besprechung zur personellen Einzelmaßnahme
```

**Expected flags**

- keyword: `Betriebsrat`
- keyword: `personelle Einzelmaßnahme` if configured

**Expected outcome**

- Risk level: `SENSITIVE_PII` or keyword-based warning level
- Decision: `ALLOW_WITH_WARNING`
- Audit trail should show keyword hit source

---

### 2. Confidential contract draft

**Example content**

```text
Strictly confidential
Draft service agreement
Not for external distribution
```

**Expected flags**

- keyword: `strictly confidential`
- keyword: `not for external distribution`

**Expected outcome**

- Risk level: `SENSITIVE_PII` or confidentiality warning
- Decision: `ALLOW_WITH_WARNING`

---

### 3. Legal / procurement material

**Example content**

```text
EVB-IT Vertrag
Vergabeverfahren
VOB Abweichung
```

**Expected flags**

- legal/procurement keywords depending on configured YAML list

**Expected outcome**

- warning banner because the document is likely sensitive business material

---

### 4. Finance and audit planning

**Example content**

```text
Jahresabschluss 2026
Steuerprüfung vorbereitet
Bilanzentwurf intern
```

**Expected flags**

- finance keywords like `Jahresabschluss`, `Steuerprüfung`, `Bilanz`

**Expected outcome**

- warning banner even if no PII exists

---

## Cases that should be handled carefully

### 1. Generic words with multiple meanings

**Example content**

```text
This is a draft plan for a workshop.
```

**Risk**

- a broad keyword like `draft` alone is too generic

**Action**

- prefer phrases, domain terms, or weighted combinations instead of weak single words

---

### 2. Department names without sensitive context

**Example content**

```text
Meeting with Finance next week.
```

**Risk**

- `Finance` by itself may be too broad to justify a warning

**Action**

- use multi-keyword rules or score-based matching for low-specificity terms

---

## Operational note

Keyword rules should remain tenant-specific and editable because they reflect internal language, project names, council terms, and business sensitivity definitions unique to each organisation.
