"""Spawn Ghidra headless with the LibGhidraHeadlessServer postScript and wait for HTTP up.

Lifecycle:
    runner = HeadlessRunner(binary, project_dir, port)
    runner.start()        # blocks until HTTP responds
    ... use libghidra client on http://127.0.0.1:<port> ...
    runner.stop()         # terminate subprocess + clean up

Or via context manager:
    with HeadlessRunner(binary, project_dir, port) as r:
        ...

Notes
-----
analyzeHeadless writes its project files into <project_dir>/<project_name>.{gpr,rep}.
We use a unique project_name per run so concurrent analyses don't collide.
"""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import httpx


def _is_windows() -> bool:
    return sys.platform.startswith("win")


def _analyze_headless_path(ghidra_home: Path) -> Path:
    script = "analyzeHeadless.bat" if _is_windows() else "analyzeHeadless"
    return ghidra_home / "support" / script


def _wait_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1.0):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _wait_http(url: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            r = httpx.get(url, timeout=2.0)
            if r.status_code < 500:
                return True
        except httpx.HTTPError:
            time.sleep(0.5)
    return False


@dataclass
class HeadlessRunner:
    binary: Path
    project_dir: Path
    ghidra_home: Path
    port: int = 18080
    project_name: str = field(default_factory=lambda: f"theseus-{uuid.uuid4().hex[:8]}")
    startup_timeout: float = 180.0   # Ghidra auto-analysis can be slow on big binaries
    log_cb: Optional[Callable[[str], None]] = None
    _proc: Optional[subprocess.Popen] = field(default=None, init=False, repr=False)
    _log_path: Optional[Path] = field(default=None, init=False, repr=False)

    def _log(self, msg: str) -> None:
        if self.log_cb:
            self.log_cb(msg)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("HeadlessRunner already started")

        binary = Path(self.binary).resolve()
        if not binary.exists():
            raise FileNotFoundError(f"binary not found: {binary}")

        ghidra_home = Path(self.ghidra_home).resolve()
        headless = _analyze_headless_path(ghidra_home)
        if not headless.exists():
            raise FileNotFoundError(f"analyzeHeadless not found at {headless}")

        project_dir = Path(self.project_dir).resolve()
        project_dir.mkdir(parents=True, exist_ok=True)

        cmd = [
            str(headless),
            str(project_dir),
            self.project_name,
            "-import", str(binary),
            "-postScript", "LibGhidraHeadlessServer.java", f"port={self.port}",
            "-deleteProject",   # cleanup project dir on exit
        ]
        self._log(f"[ghidra] launching: {' '.join(cmd)}")

        self._log_path = project_dir / f"{self.project_name}.log"
        log_fh = open(self._log_path, "wb")
        self._proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(project_dir),
        )

        self._log(f"[ghidra] pid={self._proc.pid} waiting for HTTP on :{self.port}")
        if not _wait_port("127.0.0.1", self.port, self.startup_timeout):
            self._dump_tail()
            self.stop()
            raise TimeoutError(
                f"Ghidra headless did not open port {self.port} within {self.startup_timeout}s. "
                f"See log: {self._log_path}"
            )
        # extra grace: HTTP server itself should respond
        if not _wait_http(self.base_url + "/", timeout=30.0):
            self._dump_tail()
            self.stop()
            raise TimeoutError("Port open but HTTP not responding (postScript may have errored)")

        self._log(f"[ghidra] HTTP up at {self.base_url}")

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=5.0)
        finally:
            self._proc = None
            self._log("[ghidra] stopped")

    def _dump_tail(self) -> None:
        if not self._log_path or not self._log_path.exists():
            return
        try:
            tail = self._log_path.read_bytes()[-4096:].decode(errors="replace")
            self._log(f"[ghidra] log tail:\n{tail}")
        except OSError:
            pass

    def __enter__(self) -> "HeadlessRunner":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()


def find_free_port(start: int = 18080, end: int = 18200) -> int:
    for port in range(start, end):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"no free port in range {start}-{end}")


@dataclass
class GhidrasqlRunner:
    """Spawn ghidrasql --http as a SQL HTTP frontend over a libghidra HTTP server.

    Binary is resolved from `binary` arg, then $GHIDRASQL_BIN, then PATH.
    """

    libghidra_url: str
    port: int = 8081
    binary: Optional[str] = None
    startup_timeout: float = 30.0
    log_cb: Optional[Callable[[str], None]] = None
    _proc: Optional[subprocess.Popen] = field(default=None, init=False, repr=False)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _log(self, msg: str) -> None:
        if self.log_cb:
            self.log_cb(msg)

    def _resolve_binary(self) -> str:
        candidate = self.binary or os.environ.get("GHIDRASQL_BIN") or "ghidrasql"
        return shutil.which(candidate) or candidate

    def start(self) -> None:
        if self._proc is not None:
            raise RuntimeError("GhidrasqlRunner already started")
        exe = self._resolve_binary()
        cmd = [exe, "--url", self.libghidra_url, "--http", "--port", str(self.port), "--max-runtime", "0"]
        self._log(f"[ghidrasql] launching: {' '.join(cmd)}")
        self._proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if not _wait_port("127.0.0.1", self.port, self.startup_timeout):
            self.stop()
            raise TimeoutError(f"ghidrasql did not bind :{self.port} in {self.startup_timeout}s")
        self._log(f"[ghidrasql] HTTP up at {self.base_url}")

    def stop(self) -> None:
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._proc.kill()
                self._proc.wait(timeout=2.0)
        finally:
            self._proc = None
            self._log("[ghidrasql] stopped")

    def __enter__(self) -> "GhidrasqlRunner":
        self.start()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.stop()
