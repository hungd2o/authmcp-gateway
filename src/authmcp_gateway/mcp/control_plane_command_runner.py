"""Bounded direct-argv subprocess execution for management profiles."""

from __future__ import annotations

import subprocess
import threading
import time
from typing import BinaryIO

from .control_plane_native_client import ManagementUnavailableError

MAX_OUTPUT_BYTES = 256 * 1024


def run_command(
    executable: str, argv: list[str], *, cwd: str | None = None, env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run a reviewed command without a shell or unbounded output buffering.

    ``env`` must be a pre-scrubbed environment (see
    ``CommandProvider._env``); passing ``None`` inherits the caller's full
    environment, so callers that spawn untrusted/third-party executables
    must always build and pass a minimal env explicitly.
    """
    try:
        process = subprocess.Popen(
            [executable, *argv], cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            shell=False,
        )
    except OSError as exc:
        raise ManagementUnavailableError("management command is unavailable") from exc
    exceeded, lock, total = threading.Event(), threading.Lock(), [0]
    stdout, stderr = bytearray(), bytearray()
    stdout_thread = threading.Thread(target=_drain, args=(process.stdout, stdout, total, lock, exceeded), daemon=True)
    stderr_thread = threading.Thread(target=_drain, args=(process.stderr, stderr, total, lock, exceeded), daemon=True)
    stdout_thread.start()
    stderr_thread.start()
    deadline = time.monotonic() + 300
    while process.poll() is None and not exceeded.is_set() and time.monotonic() < deadline:
        time.sleep(0.02)
    if process.poll() is None:
        process.kill()
        process.wait()
    stdout_thread.join()
    stderr_thread.join()
    if exceeded.is_set():
        raise ManagementUnavailableError("management command output is too large")
    if process.returncode != 0:
        raise ManagementUnavailableError("management command failed")
    return subprocess.CompletedProcess(
        [executable, *argv], process.returncode,
        stdout.decode("utf-8", errors="replace"), stderr.decode("utf-8", errors="replace"),
    )


def _drain(
    stream: BinaryIO | None, buffer: bytearray, total: list[int], lock: threading.Lock,
    exceeded: threading.Event,
) -> None:
    if stream is None:
        return
    while chunk := stream.read(8 * 1024):
        with lock:
            remaining = MAX_OUTPUT_BYTES - total[0]
            if remaining > 0:
                buffer.extend(chunk[:remaining])
            total[0] += len(chunk)
            if total[0] > MAX_OUTPUT_BYTES:
                exceeded.set()
