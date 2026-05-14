# Phase 1 — Triage

**Goal:** Produce a fast, cheap overview of the binary. Target: under 90 seconds, under 8k output tokens.

## Steps

1. Identify architecture, file format, and entry point.
   - `SELECT * FROM program_info LIMIT 1;` (or equivalent metadata table)
2. Count functions, imports, strings. Run the queries; do not guess.
   - `SELECT COUNT(*) FROM funcs;`
   - `SELECT COUNT(*) FROM imports;`
   - `SELECT COUNT(*) FROM strings;`
   - **Invariant:** `import_count` MUST be >= `len(notable_imports)`. If you
     surface any item in `notable_imports`, the count cannot be 0. For kernel
     drivers, fall back to `SELECT COUNT(DISTINCT name) FROM imports;` or
     count distinct rows from `external_symbols` / `external_functions` if
     the `imports` table is empty.
3. Pack detection — check section entropy / .text vs .data ratio / suspiciously few imports / "UPX" markers in section names.
   - `SELECT name, size, entropy FROM memory_blocks;`
   - `SELECT name FROM imports WHERE name LIKE 'UPX%' OR name LIKE '%packed%';`
4. Pull the top 15 imports ranked by suspicion. Categories worth flagging:
   - **network**: `WinHttp*`, `WSA*`, `connect`, `send`, `recv`, `getaddrinfo`, `curl_*`
   - **process**: `CreateProcess*`, `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`, `NtCreateThreadEx`, `fork`, `execve`
   - **filesystem**: `CreateFile*`, `MoveFile*`, `DeleteFile*`, `open`, `unlink`
   - **registry**: `RegOpenKey*`, `RegSetValue*`, `RegCreateKey*`
   - **crypto**: `Crypt*`, `BCrypt*`, `AES_*`, `EVP_*`
   - **anti-debug**: `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQueryInformationProcess`, `ptrace`
   - **anti-vm**: `cpuid`-heavy paths, VMware/VirtualBox-named strings
   - **injection / persistence**: `SetWindowsHookEx`, `LoadLibrary*` + `GetProcAddress` combo, `schtasks`, `crontab`
5. Sample up to 20 interesting strings (length 6+ bytes, with xrefs). Skip generic Windows error strings. Prioritize:
   - URLs, IPs, domains
   - Mutex names (`Global\\...`, `Local\\...`)
   - Registry keys (`Software\\...`, `HKLM\\...`)
   - File paths suggestive of persistence (`Startup\\`, `Run\\`)
   - Suspicious commands (`powershell`, `cmd /c`, `bash -i`, `wget`, `curl`)

## Suspicion scoring rubric

Start at 0. Add:

- +10 per network import in top imports
- +15 if `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` all present (process hollowing)
- +10 if anti-debug imports present
- +10 if anti-vm strings present
- +15 if packed
- +20 if registry persistence path strings xref'd by code
- +10 if `LoadLibrary` + `GetProcAddress` pattern dominates control flow
- +5 per credible IoC string (URL/IP/mutex)

Cap at 100.

## Output (strict JSON, no prose)

```json
{
  "entry_point": "0x401000",
  "arch": "x86:LE:64:default",
  "format": "PE",
  "packed": false,
  "pack_evidence": "",
  "suspicion_score": 45,
  "function_count": 312,
  "import_count": 84,
  "string_count": 1204,
  "notable_imports": [
    {"name": "WinHttpOpen", "category": "network", "reason": "HTTP client setup"},
    {"name": "VirtualAllocEx", "category": "injection", "reason": "Remote memory allocation primitive"}
  ],
  "notable_strings": [
    {"value": "http://c2.example.com/beacon", "address": "0x10040020", "category": "url"}
  ]
}
```
