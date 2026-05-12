# Theseus

> Navigate any binary.

AI-assisted reverse-engineering pipeline. Drop a binary, get a structured triage report with MITRE ATT&CK mapping, IoCs, and a SOC-actionable verdict.

Built on:

- [Ghidra](https://ghidra-sre.org/) — NSA's reverse-engineering suite (analysis engine)
- [libghidra](https://github.com/0xeb/libghidra) — typed Python SDK for headless Ghidra
- [ghidrasql](https://github.com/0xeb/ghidrasql) — SQL over a Ghidra program database
- [ghidrasql-skills](https://github.com/0xeb/ghidrasql-skills) — Claude Code agent skills
- [DearPyGui](https://github.com/hoffstadt/dearpygui) — GUI
- [reveal.js](https://revealjs.com/) — demo deck output

## Mythology

In the Labyrinth, **Daedalus** built the maze, **Theseus** navigated it, and **Ariadne's thread** kept him oriented. A compiled binary is a labyrinth: the compiler/obfuscator is Daedalus, the analyst is Theseus, and the AI agent — guided by the skills chain — is Ariadne's thread.

## Architecture

```
GUI (DearPyGui)
   |
   v
orchestrator.py  ---->  Anthropic Claude (Agent SDK)
   |                         |
   |                         | tool calls (ghidrasql HTTP)
   v                         v
headless Ghidra <--- LibGhidraHost HTTP :18080
   (analyzeHeadless + LibGhidraHeadlessServer.java)
```

Phases (each = focused prompt, JSON output):

1. **Triage** — funcs/imports/strings overview, pack detection, suspicion score
2. **Capability** — MITRE ATT&CK technique mapping with evidence
3. **IoC** — URLs, IPs, mutex, regkey, paths (xref-validated)
4. **Verdict** — clean / suspicious / vulnerable (BYOVD) / malicious / unknown + SOC action recommendation

Final output: `report.json` (schema in `schema/report.schema.json`) plus an HTML reveal.js deck for demos.

## Install

Prereqs:

- Windows 10/11 or Linux
- Python 3.12+
- Ghidra 12.1+ (https://github.com/NationalSecurityAgency/ghidra/releases)
- JDK 21 (for Ghidra)
- LibGhidraHost extension built and installed in Ghidra
- An Anthropic API key (or Claude Code with the ghidrasql-skills plugin)

```bash
git clone <this-repo> theseus
cd theseus
python -m venv .venv && source .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -r requirements.txt
cp .env.example .env   # fill in ANTHROPIC_API_KEY, GHIDRA_HOME
```

## Usage

CLI:

```bash
theseus run path/to/binary.exe                # single binary, prints + writes report.json
theseus run binary.exe --deck report.html     # also generate reveal.js demo deck
theseus serve --port 8090                     # HTTP API for SOC ingest
```

GUI:

```bash
theseus gui
```

Drop a binary on the window. Watch the pipeline tabs fill. Open the deck when done.

## SOC integration

```bash
# Push verdict to a SOAR webhook
theseus run binary.exe --webhook https://soar.internal/ingest
```

JSON output is schema-stable. See `schema/report.schema.json`.

## Sample data

- [crackmes.one](https://crackmes.one) — legal RE practice binaries
- [MalwareBazaar](https://bazaar.abuse.ch) — real malware (**isolated VM only**)
- Always analyze unknown binaries inside FlareVM, REMnux, or a network-isolated VM

## License

Project: TBD. Upstream (Ghidra: Apache 2.0; libghidra/ghidrasql: see upstream repos).
