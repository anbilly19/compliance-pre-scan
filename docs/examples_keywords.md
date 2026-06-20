# Detection examples — keywords and confidentiality markers

Keyword matching uses Aho-Corasick pattern matching against configurable YAML lists. It runs after PII and secret scanning as a third signal layer.

---

## Keyword lists

Lists live in `config/keywords/`. Each YAML file contains a list of terms (case-insensitive by default).

| File | Sample triggers |
|------|-----------------|
| `confidentiality.yaml` | Geheimhaltungsvereinbarung, NDA, vertraulich, confidential, internal only, unter Verschluss |
| `hr.yaml` | Betriebsrat, Personalakte, Gehalt, Lohnabrechnung, Kündigung, Abmahnung, Zeugnis |
| `finance.yaml` | Jahresabschluss, Bilanz, Gewinn und Verlust, Steuerprüfung, IBAN, Kontonummer |
| `legal.yaml` | EVB-IT, Vergaberecht, VOB, Rechtsstreit, Klage, Vergleich, Schadensersatz |

---

## Policy outcome

- Any keyword hit → `risk_level=SENSITIVE_PII`, `decision=ALLOW_WITH_WARNING`, HTTP 200
- Keywords never trigger a BLOCK on their own — they are a soft signal
- The `reason` field will be `keyword_match`
- If PII or secrets are also present, the higher-severity decision takes precedence (BLOCK beats WARNING)

---

## Hit masking (`MASK_SNIPPETS=true`)

Keyword hits pass through masking **unchanged** — the matched term itself is not sensitive (it is a category label, not personal data):

| Original | Masked |
|----------|--------|
| `Betriebsrat` | `Betriebsrat` |
| `CONFIDENTIAL` | `CONFIDENTIAL` |
| `Personalakte` | `Personalakte` |

---

## Adding custom keywords

Add a new YAML file to `config/keywords/` and reference it in `KEYWORD_CONFIG_PATHS` in `.env`:

```yaml
# config/keywords/projects.yaml
- Project Phoenix
- Projekt Alpha
- client-XYZ
- internal-reference-12345
```

```env
KEYWORD_CONFIG_PATHS=config/keywords/confidentiality.yaml,config/keywords/hr.yaml,config/keywords/projects.yaml
```

No restart required if using OPA for policy — keyword lists are loaded at scanner initialisation, so a service restart is needed to pick up changes.

---

## Tuning weak signals

- Very common German words (`Vertrag`, `Rechnung`) that appear in routine docs may produce noise — remove them from the list or move them to a separate lower-priority list
- Combine keyword hits with PII count in the policy to raise severity: e.g. use OPA/Rego to add a custom rule that blocks when `keyword_count > 0 AND pii_count > 5`
