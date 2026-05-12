# LibGhidraHost extension — install + verify

Theseus drives Ghidra headless through the `LibGhidraHost` extension. The
extension ships a Java RPC server inside Ghidra; `ghidrasql` (and Theseus
itself) speak HTTP/protobuf to that server.

Set `GHIDRA_INSTALL_DIR` to your Ghidra distribution root (the directory
that contains `support/`, `Ghidra/`, and `ghidraRun*`):

```powershell
# Windows (PowerShell)
$env:GHIDRA_INSTALL_DIR = "C:\path\to\ghidra_12.X_PUBLIC"
```

```bash
# POSIX
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.X_PUBLIC
```

## Build + install the extension

Clone <https://github.com/0xeb/libghidra> next to this repository (or
anywhere convenient) and build via Gradle:

```bash
git clone https://github.com/0xeb/libghidra.git
cd libghidra/ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
```

After install, the extension lives at:

```
$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/
```

…and the headless launcher script at:

```
$GHIDRA_INSTALL_DIR/Ghidra/Extensions/LibGhidraHost/ghidra_scripts/LibGhidraHeadlessServer.java
```

## Enable in the Ghidra GUI (optional)

Only needed if you want to attach to an already-running Ghidra session.
Theseus's pipeline spawns its own headless instance, so the GUI is not
required for `theseus run`.

1. Launch Ghidra: `$GHIDRA_INSTALL_DIR/ghidraRun` (`.bat` on Windows).
2. **File → Configure → Miscellaneous**, tick **LibGhidraHost**, click OK.
3. Restart Ghidra if prompted.
4. Open a program in CodeBrowser.
5. **Tools → libghidra Host → Start Server…** → accept default port `18080`.
6. **Tools → libghidra Host → Status** should show running.

Verify from a shell:

```bash
curl http://127.0.0.1:18080/
# expect: "libghidra host\nPOST /rpc (...)\nGET  /help"
```

The endpoint is `POST /rpc` with a binary protobuf body
(`libghidra.RpcRequest`); the libghidra Python SDK wraps this.

## Headless mode (used by Theseus)

Theseus's `HeadlessRunner` already invokes:

```bash
$GHIDRA_INSTALL_DIR/support/analyzeHeadless \
    <project-dir> <project-name> \
    -import <binary> \
    -postScript LibGhidraHeadlessServer.java port=<auto> \
    -deleteProject
```

You should not need to run this manually. See
`src/theseus/headless_runner.py` for the source of truth.

## Re-build after pulling libghidra updates

```bash
cd <libghidra_repo>
git pull
cd ghidra-extension
gradle installExtension -PGHIDRA_INSTALL_DIR="$GHIDRA_INSTALL_DIR"
```

Restart Ghidra after a rebuild for the new jar to be loaded.
