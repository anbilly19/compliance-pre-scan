# Detection examples — secrets and credentials

Secret scanning uses a custom regex ruleset inspired by Gitleaks, written from scratch (MIT, no GPL). It runs on extracted text and also on raw file content for binary-safe patterns.

---

## What triggers a secret hit

| Pattern | Example match | Severity |
|---------|--------------|----------|
| AWS Access Key | `AKIAIOSFODNN7EXAMPLE` | HIGH |
| AWS Secret Key | `aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/...` | HIGH |
| Generic API key | `api_key = "sk-abc123..."`, `token: "ghp_..."` | HIGH |
| JWT | `eyJhbGciOiJIUzI1NiJ9.eyJ...` | HIGH |
| Database URI | `postgresql://user:pass@host:5432/db` | HIGH |
| Private key PEM | `-----BEGIN RSA PRIVATE KEY-----` | HIGH |
| Password in config | `password = "s3cr3t"`, `passwd: hunter2` | MEDIUM |
| Generic secret | `SECRET_KEY = "abc"`, `secret = "..."` | MEDIUM |

---

## Policy outcome

- Secret count ≥ `SECRET_WARN_THRESHOLD` (default: 1) → `ALLOW_WITH_WARNING`, HTTP 200
- Secret count ≥ `BLOCK_ON_SECRET` (default: 1) → **`BLOCK`, HTTP 451**
- Because both thresholds default to 1, **any single secret hit blocks the upload by default**
- The `reason` field will be `block_on_secret`

To switch to warn-only mode: set `BLOCK_ON_SECRET=0` in `.env`.

---

## Hit masking (`MASK_SNIPPETS=true`)

Secret snippets are aggressively masked — only the first 4 characters are kept:

| Original | Masked |
|----------|--------|
| `AKIAIOSFODNN7EXAMPLE` | `AKIA****` |
| `postgresql://user:s3cr3t@host/db` | `post****` |
| `eyJhbGciOiJIUzI1NiJ9...` | `eyJh****` |
| `-----BEGIN RSA PRIVATE KEY-----` | `----****` |

Rule: keep first 4 characters, replace the rest with `****`.

---

## Placeholder / test credential suppression

Common placeholder patterns (`password = "changeme"`, `secret = "example"`, `token = "YOUR_TOKEN_HERE"`) are suppressed by default to avoid flooding the audit log during development.

See the ruleset comments in `src/compliance_scan/scanners/secret_scanner.py` for the full exclusion list.

---

## Tuning

- Set `BLOCK_ON_SECRET=0` to switch to warn-only (not recommended for production)
- Add organisation-specific secret patterns to `config/keywords/confidentiality.yaml`
- All secrets are always HIGH or MEDIUM — they are never suppressed by the false-positive classifier
