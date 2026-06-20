# Detection examples — secrets and credentials

This document shows examples of content that should trigger secret or credential detection.

The system raises a secret-related concern when extracted text matches known patterns for API keys, tokens, connection strings, private keys, or plaintext credentials. In the current implementation, any such hit leads to `risk_level = SECRET_FOUND` and `decision = ALLOW_WITH_WARNING`.

---

## Typical cases that should be flagged

### 1. API key in config snippet

**Example content**

```text
OPENAI_API_KEY=sk-test-1234567890abcdef
```

**Expected flags**

- Generic API key pattern
- Secret scanner hit with `severity = HIGH`

**Expected outcome**

- Risk level: `SECRET_FOUND`
- Decision: `ALLOW_WITH_WARNING`

---

### 2. Database connection string

**Example content**

```text
DATABASE_URL=postgresql://app_user:SuperSecret123@db.internal.local:5432/customerdb
```

**Expected flags**

- database URI pattern
- password exposure in connection string

**Expected outcome**

- Risk level: `SECRET_FOUND`
- Decision: `ALLOW_WITH_WARNING`

---

### 3. JWT in logs or exports

**Example content**

```text
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature
```

**Expected flags**

- JWT token structure

**Expected outcome**

- Risk level: `SECRET_FOUND`
- Decision: `ALLOW_WITH_WARNING`

---

### 4. Private key material

**Example content**

```text
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA...
-----END RSA PRIVATE KEY-----
```

**Expected flags**

- private key PEM block

**Expected outcome**

- Risk level: `SECRET_FOUND`
- Decision: `ALLOW_WITH_WARNING`

---

## Cases that may need tuning

### 1. Placeholder secrets in documentation

**Example content**

```text
Set api_key="your-api-key-here" in the config file.
```

**Desired behaviour**

- ideally not treated the same as a real live key
- may still match a loose generic secret pattern if rules are too broad

**Action**

- tighten regexes or add allowlist patterns for placeholders like `your-api-key-here`, `changeme`, `example-token`

---

### 2. Sample JWTs in documentation

**Example content**

```text
eyJhbGciOi...example...signature
```

**Desired behaviour**

- flagging is acceptable in strict mode
- in production, you may want a separate rule severity for example tokens vs likely live tokens

---

## Operational note

Secrets should stay the highest-priority business concern because even one valid key or connection string is enough to leak infrastructure access into the chat workflow.
