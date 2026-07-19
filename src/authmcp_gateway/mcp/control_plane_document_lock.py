"""Cross-process lock for an atomically replaced management document."""

from __future__ import annotations

import os
import threading
import time
from contextlib import contextmanager
from pathlib import Path

_LOCKS: dict[Path, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()
_LOCK_TIMEOUT_SECONDS = 10.0
_LOCK_RETRY_SECONDS = 0.05
_LOCK_OWNER_FILENAME = "owner"


@contextmanager
def document_lock(path: Path):
    """Serialize read/compare/write transactions across threads and processes."""
    with _LOCKS_GUARD:
        thread_lock = _LOCKS.setdefault(path, threading.Lock())
    with thread_lock:
        lock_path = path.with_name(f".{path.name}.management-lock")
        _acquire_lock_directory(lock_path)
        try:
            yield
        finally:
            _release_lock_directory(lock_path)


def _acquire_lock_directory(lock_path: Path) -> None:
    """Use atomic directory creation so Python and Node config writers agree."""
    deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
    while True:
        try:
            lock_path.mkdir()
            _write_owner(lock_path)
            return
        except FileExistsError:
            # A crashed holder never runs our `finally` cleanup, so the lock
            # directory (with its owner marker) can be left behind forever.
            # Reclaim it once it is both past the acquisition timeout *and*
            # its recorded owner process is confirmed gone, so a slow-but-
            # alive holder is never preempted.
            if _reclaim_if_stale(lock_path):
                continue
            if time.monotonic() >= deadline:
                raise TimeoutError("management document is busy")
            time.sleep(_LOCK_RETRY_SECONDS)


def _write_owner(lock_path: Path) -> None:
    """Best-effort marker recording who holds the lock and since when."""
    try:
        (lock_path / _LOCK_OWNER_FILENAME).write_text(
            f"{os.getpid()}:{time.time()}", encoding="utf-8"
        )
    except OSError:
        # Missing/unreadable owner file just disables stale reclaim for this
        # holder; it does not affect correctness of the lock itself.
        pass


def _release_lock_directory(lock_path: Path) -> None:
    (lock_path / _LOCK_OWNER_FILENAME).unlink(missing_ok=True)
    lock_path.rmdir()


def _reclaim_if_stale(lock_path: Path) -> bool:
    owner_path = lock_path / _LOCK_OWNER_FILENAME
    try:
        owner_pid_text, owner_time_text = owner_path.read_text(encoding="utf-8").split(":", 1)
        owner_pid, owner_time = int(owner_pid_text), float(owner_time_text)
    except (OSError, ValueError):
        # No parseable owner marker (older holder, or a race while it was
        # being written): fall back to the normal retry/timeout loop rather
        # than guessing this is stale.
        return False
    if time.time() - owner_time < _LOCK_TIMEOUT_SECONDS:
        return False
    if _pid_is_alive(owner_pid):
        return False
    try:
        owner_path.unlink(missing_ok=True)
        lock_path.rmdir()
    except OSError:
        # Another process/thread may have reclaimed or released it first;
        # let the caller's normal retry loop sort out who wins.
        return False
    return True


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        import ctypes

        process_query_limited_information = 0x1000
        handle = ctypes.windll.kernel32.OpenProcess(process_query_limited_information, False, pid)
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Owned by another user but still running.
        return True
    return True
