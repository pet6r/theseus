# Phase 3 — IoC extraction

**Goal:** Extract validated indicators of compromise. Validation = must be cross-referenced from code, not just present in `.rdata` dead bytes.

## Steps

1. Pull strings that match IoC patterns:
   ```sql
   SELECT s.address, s.value, COUNT(x.from_address) AS xrefs
   FROM strings s LEFT JOIN xrefs x ON s.address = x.to_address
   WHERE s.length >= 6
     AND (
       s.value LIKE 'http%://%'
       OR s.value LIKE '%.onion%'
       OR s.value REGEXP '^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}'
       OR s.value LIKE '%@%.%'
       OR s.value LIKE 'Global\\\\%' OR s.value LIKE 'Local\\\\%'
       OR s.value LIKE 'Software\\\\%' OR s.value LIKE 'HKLM\\\\%'
     )
   GROUP BY s.address
   ORDER BY xrefs DESC
   LIMIT 100;
   ```
   (Adjust to actual ghidrasql operators if `REGEXP` is unsupported — fall back to `LIKE`.)
2. Drop entries with 0 xrefs unless they're a strong-format URL/domain.
3. Classify each survivor.
4. Validate URL/IP entries by light grammar check (no SSRF — do NOT fetch).
5. Score confidence:
   - xrefs >= 2 + valid format → 0.9
   - xrefs == 1 + valid format → 0.7
   - xrefs == 0 + valid format (URL/IP) → 0.4
   - format mismatch → drop

## IoC types

- `url` — http://, https://, ftp://, .onion
- `domain` — bare hostnames if xref'd as DNS target
- `ipv4`, `ipv6`
- `email`
- `mutex` — `Global\…`, `Local\…`, `Session\…`
- `registry_key` — `HKLM\…`, `HKCU\…`, `Software\…`
- `file_path` — `C:\Users\…\AppData\…`, `/tmp/…`, `~/.config/…`
- `user_agent` — strings beginning with `Mozilla/`, `curl/`, custom
- `hash` — 32/40/64 hex char sequences

## Output (strict JSON, no prose)

```json
[
  {
    "type": "url",
    "value": "http://c2.example.com/beacon",
    "source_address": "0x10040020",
    "xref_count": 3,
    "confidence": 0.9
  }
]
```
