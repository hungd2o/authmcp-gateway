"""Runtime state (PID file) management for the background server lifecycle.

The gateway persists the PID of the process that owns the system tray + uvicorn
server to a small state file.  The CLI launcher uses it to answer three
questions without importing the heavy application stack:

* Is a gateway already running?  (skip spawning a duplicate)
* Which process should ``stop`` signal?
* What should ``status`` report?
"""

from __future__ import annotations

import os
import signal
import socket
import time
from pathlib import Path

_PID_FILE = Path("data") / "authmcp-gateway.pid"


def _pid_file() -> Path:
    return _PID_FILE


def read_pid() -> int | None:
    """Return the PID recorded in the state file, or ``None`` if absent/invalid."""
    try:
        text = _pid_file().read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        return int(text)
    except ValueError:
        return None


def is_process_running(pid: int) -> bool:
    """Return ``True`` if a process with *pid* is currently alive."""
    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _windows_pid_alive(pid: int) -> bool:
    """Return ``True`` when a Windows process with *pid* is still active."""
    import ctypes

    process_query_limited_information = 0x1000
    still_active = 259
    kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
    handle = kernel32.OpenProcess(process_query_limited_information, False, pid)
    if not handle:
        return False
    try:
        exit_code = ctypes.c_ulong()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return False
        return exit_code.value == still_active
    finally:
        kernel32.CloseHandle(handle)


def get_running_pid() -> int | None:
    """Return the PID of a live gateway, else ``None``.

    Clears the state file when it references a process that is no longer alive
    so stale files never block a fresh launch.
    """
    pid = read_pid()
    if pid is None:
        return None
    if is_process_running(pid):
        return pid
    clear_pid()
    return None


def write_pid(pid: int) -> None:
    """Persist *pid* to the state file, creating the directory if needed."""
    path = _pid_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(pid), encoding="utf-8")


def clear_pid() -> None:
    """Remove the state file if present (idempotent)."""
    try:
        _pid_file().unlink()
    except OSError:
        pass


def stop_process(pid: int) -> bool:
    """Signal the process identified by *pid* to stop.

    Returns ``True`` when the stop signal was delivered.  On Windows this maps
    to ``TerminateProcess``; on POSIX it sends ``SIGTERM`` so uvicorn and the
    tray can shut down cleanly.
    """
    if not is_process_running(pid):
        return False
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        return False
    return True


def _connect_host(host: str) -> str:
    """Map a bind host to an address usable for a client connection check."""
    if host in ("0.0.0.0", "", "::"):
        return "127.0.0.1"
    return host


def is_port_in_use(host: str, port: int, timeout: float = 0.5) -> bool:
    """Return ``True`` when a TCP connection to ``(host, port)`` succeeds.

    This is the authoritative "is the gateway actually up?" signal — it reflects
    reality even when the PID file is stale or the port was taken by an
    unrelated process.
    """
    try:
        with socket.create_connection((_connect_host(host), port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(
    host: str, port: int, timeout: float = 15.0, interval: float = 0.25
) -> bool:
    """Poll until ``(host, port)`` accepts connections or ``timeout`` elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if is_port_in_use(host, port):
            return True
        time.sleep(interval)
    return False
