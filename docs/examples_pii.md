# Detection examples — PII

PII detection uses [Microsoft Presidio](https://github.com/microsoft/presidio) (MIT) with bilingual EN + DE NER models and regex recognisers. Detection runs on extracted text only — no file content is sent to any external service.

---

## What triggers a PII hit

| Entity type | Example | Severity | Notes |
|-------------|---------|----------|---------|
| `EMAIL_ADDRESS` | `max.mustermann@firma.de` | HIGH | Regex |
| `PHONE_NUMBER` | `+49 211 1234567`, `0211/123456` | HIGH | DE + EN patterns |
| `IBAN_CODE` | `DE89 3704 0044 0532 0130 00` | HIGH | Checksum validated |
| `CREDIT_CARD` | `4111 1111 1111 1111` | HIGH | Luhn validated |
| `PERSON` | `Max Mustermann`, `Anna Schmidt` | MEDIUM | spaCy NER |
| `LOCATION` | Street address, city | MEDIUM | Suppressed in financial/technical docs |
| `ORGANIZATION` | Company names | MEDIUM | Suppressed in financial/technical docs |
| `IP_ADDRESS` | `192.168.1.1`, `10.0.0.1` | LOW | Regex |
| `DATE_TIME` | `01.01.1985`, `1985-01-01` | LOW | Context-dependent |

---

## Policy outcome

- Any PII hit ≥ `PII_WARN_THRESHOLD` (default: 1) → `ALLOW_WITH_WARNING`, HTTP 200
- PII hits ≥ `BLOCK_ON_PII` (default: 0, disabled) → `BLOCK`, HTTP 451
- The `reason` field in the result will be `pii_warn` or `block_on_pii`

---

## Hit masking (`MASK_SNIPPETS=true`)

PII snippets are masked before being written to the audit log and returned in the API response:

| Original | Masked |
|----------|--------|
| `max.mustermann@firma.de` | `ma***de` |
| `+49 211 1234567` | `+4***67` |
| `DE89 3704 0044 0532 0130 00` | `DE***00` |
| `Max Mustermann` | `Ma***nn` |

Rule: keep first 2 + last 2 characters, replace middle with `***`.

---

## False-positive suppression

Documents classified as **financial cost sheets** or **technical procurement docs** have `ORGANIZATION` and `LOCATION` hits automatically suppressed. NER confidence thresholds are also raised by 0.05 on these document types.

See [false_positive_suppression.md](false_positive_suppression.md) for full details.

---

## Tuning

- Raise `PII_WARN_THRESHOLD` in `.env` to reduce noise for documents with many incidental names
- Enable `BLOCK_ON_PII` (e.g. `BLOCK_ON_PII=10`) for high-security environments
- HIGH-severity types (`EMAIL_ADDRESS`, `PHONE_NUMBER`, `IBAN_CODE`, `CREDIT_CARD`) are never suppressed by the false-positive classifier
