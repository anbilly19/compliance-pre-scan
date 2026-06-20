# Detection examples — structural anomalies and suspicious files

The anomaly scanner runs on the raw file (not extracted text) and checks for structural red flags that may indicate a disguised payload, embedded malicious content, or a deliberately crafted file.

---

## Checks performed

| Check | Trigger condition | Severity |
|-------|-------------------|----------|
| Extension mismatch | MIME magic ≠ declared extension (e.g. `.pdf` but binary is EXE) | HIGH |
| High entropy | Shannon entropy > `ENTROPY_HIGH_THRESHOLD` (default: 7.2) on file chunks — suggests encrypted or compressed payload hidden inside | MEDIUM |
| Size vs text ratio | `file_size_bytes / len(extracted_text) > SIZE_RATIO_THRESHOLD` (default: 50) — large file, almost no readable text | MEDIUM |
| Embedded macro | DOCX/XLSX contains VBA macros or OLE objects | MEDIUM |
| Archive bomb | ZIP recursion depth > `MAX_ARCHIVE_DEPTH` (default: 2) or unpacked size exceeds limit | HIGH |

---

## Policy outcome

- **HIGH anomaly** (extension mismatch, archive bomb):
  - `BLOCK_ON_STRUCTURAL_ANOMALY=true` (default) → **`BLOCK`, HTTP 451**, `reason=block_on_structural_anomaly`
  - `BLOCK_ON_STRUCTURAL_ANOMALY=false` → `ALLOW_WITH_WARNING`, HTTP 200, `reason=high_anomaly`
- **MEDIUM anomaly** (entropy, size ratio, macro):
  - Always `ALLOW_WITH_WARNING`, HTTP 200
  - Never triggers BLOCK on its own
- `risk_level` is always `STRUCTURAL_ANOMALY` for any anomaly hit

---

## Hit masking (`MASK_SNIPPETS=true`)

Anomaly hits pass through masking **unchanged** — they contain structural metadata, not personal data:

| Original snippet | Masked |
|-----------------|--------|
| `extension_mismatch: declared=pdf detected=application/x-dosexec` | unchanged |
| `high_entropy: score=7.8 offset=0x1000` | unchanged |
| `macro_detected: vba_modules=2` | unchanged |

---

## Examples

### Extension mismatch

```
file: invoice.pdf
detected MIME: application/x-dosexec
declared MIME: application/pdf
→ HIGH anomaly: extension_mismatch
→ BLOCK (default) or ALLOW_WITH_WARNING
```

### High entropy blob

```
file: report.docx
entropy at offset 0x4000: 7.9 (threshold: 7.2)
→ MEDIUM anomaly: high_entropy
→ ALLOW_WITH_WARNING
```

### Archive bomb

```
file: data.zip
recursion depth: 4 (limit: 2)
→ HIGH anomaly: archive_bomb
→ BLOCK (default)
```

### Macro in Office file

```
file: template.docx
OLE object found: vba_modules=3
→ MEDIUM anomaly: macro_detected
→ ALLOW_WITH_WARNING
```

---

## Tuning

- Raise `ENTROPY_HIGH_THRESHOLD` (e.g. to 7.5) to reduce noise from legitimately compressed documents
- Raise `SIZE_RATIO_THRESHOLD` for environments where large binary attachments are expected
- Set `BLOCK_ON_STRUCTURAL_ANOMALY=false` if your platform commonly handles files with unusual structures and you prefer a warning-only mode
