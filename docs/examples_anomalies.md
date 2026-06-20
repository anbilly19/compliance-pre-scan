# Detection examples — anomalies and suspicious files

This document shows examples of files that should raise structural or malicious-content concerns before upload.

These checks are important because the file may be dangerous or deceptive even when the extracted text looks harmless.

---

## Typical cases that should be flagged

### 1. Extension mismatch

**Example case**

- File is named `report.pdf`
- Magic bytes identify it as an executable or generic binary

**Expected flags**

- anomaly: extension mismatch
- file identity mismatch in summary

**Expected outcome**

- Risk level: `STRUCTURAL_ANOMALY`
- Decision: `ALLOW_WITH_WARNING` now, later eligible for `BLOCK`

---

### 2. Macro-enabled office file

**Example case**

- User uploads an XLSM or DOCM file with embedded VBA project

**Expected flags**

- anomaly: macro detected
- optional escalation if macros are forbidden by policy

**Expected outcome**

- warning banner
- audit event notes structural anomaly

---

### 3. Suspiciously large file with very little text

**Example case**

- 40 MB file
- only a few lines of extracted text

**Why it matters**

- could indicate embedded payloads, excessive binary objects, or malformed content

**Expected flags**

- anomaly: high size-to-text ratio
- possibly high entropy as well

**Expected outcome**

- Risk level: `STRUCTURAL_ANOMALY`
- Decision: `ALLOW_WITH_WARNING`

---

### 4. High entropy binary chunks

**Example case**

- raw bytes contain long high-entropy regions inconsistent with a normal office document

**Why it matters**

- may indicate compressed, encrypted, or packed payloads

**Expected flags**

- anomaly: entropy threshold exceeded

**Expected outcome**

- warning banner and audit entry

---

### 5. Archive bomb or nested archive abuse

**Example case**

- ZIP file expands massively or has deep nesting

**Expected flags**

- anomaly: archive depth exceeded
- anomaly: unpacked size limit exceeded

**Expected outcome**

- should be considered a strong candidate for future `BLOCK`

---

## Cases that are noisy but not necessarily malicious

### 1. Image-heavy PDF

**Example case**

- scanned PDF brochure with almost no OCR text

**Risk**

- may trigger high size-to-text ratio even though it is benign

**Action**

- treat as warning, not immediate block
- improve OCR or file-type-specific thresholds later

---

### 2. Legitimate compressed engineering bundle

**Example case**

- archive with CAD exports and binary assets

**Risk**

- entropy and size heuristics may trigger

**Action**

- keep warning path, review thresholds per tenant or per allowed file class

---

## Operational note

Anomaly checks are the main place where future malware-oriented controls can be extended with ClamAV, YARA, or content disarm rules without changing the rest of the pipeline.
