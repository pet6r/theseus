# Phase 2 — Capability detection (MITRE ATT&CK mapping)

**Goal:** Map observed behavior to MITRE ATT&CK techniques. Each technique cited must have concrete evidence (addr + import or snippet).

## Inputs available

You already have the triage report. Use those notable_imports and notable_strings as starting points.

## Steps

1. For each notable import, decide whether a single technique is implied or whether you need to inspect the calling function. Get decompilation for ambiguous cases:
   - `get_decompilation(function_address)` on the function that calls the import.
2. For each suspicious string (e.g. registry persistence paths, beacon URLs, PowerShell commands), find the function that references it and inspect.
3. Walk the call graph from `main` or DllMain for 2-3 hops to find the orchestration function.

## Mapping cheat-sheet (non-exhaustive)

| Observation | Technique |
|-------------|-----------|
| `VirtualAllocEx` + `WriteProcessMemory` + `CreateRemoteThread` | T1055.002 (Portable Executable Injection) |
| `SetWindowsHookEx` | T1056.004 (Credential API Hooking) |
| `RegSetValueEx` writing to `Run` key | T1547.001 (Registry Run Keys) |
| `schtasks /create`, `at.exe` | T1053.005 (Scheduled Task) |
| `IsDebuggerPresent`, `CheckRemoteDebuggerPresent` | T1622 (Debugger Evasion) |
| `WinHttpOpen` → `WinHttpSendRequest` to hardcoded URL | T1071.001 (Web Protocols / C2) |
| `CryptEncrypt` / `BCryptEncrypt` over file IO loop | T1486 (Data Encrypted for Impact) |
| `wevtutil cl`, `ClearEventLog` | T1070.001 (Clear Windows Event Logs) |
| `GetProcAddress` lookup chain on hashed names | T1027.007 (Dynamic API Resolution) |
| VM string compare (`VBox`, `VMware`, `QEMU`) | T1497.001 (System Checks) |

For Linux/ELF: also consider `ptrace` anti-debug (T1622), `LD_PRELOAD` hijack (T1574.006), `crontab` persistence (T1053.003).

## Rules

- **Cite evidence.** Each technique entry must include at least one `{address, function?, snippet}` evidence item.
- **Confidence reflects evidence.** Single suggestive import alone = 0.3-0.5. Multiple corroborating imports + decompiled code path = 0.7-0.95. Smoking-gun string + matching code = up to 0.95.
- **Do not over-claim.** If you see `IsDebuggerPresent` but it's in a stub and never xref'd from a real function, it's still T1622 but low confidence (~0.3).

## Output (strict JSON, no prose)

```json
[
  {
    "technique_id": "T1055.002",
    "name": "Process Injection: Portable Executable Injection",
    "tactic": "Defense Evasion",
    "confidence": 0.85,
    "evidence": [
      {"address": "0x401820", "function": "Inject", "snippet": "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread in sequence"}
    ]
  }
]
```
