"""Tests for runtime_state PID-file lifecycle helpers."""

import os

import pytest

from authmcp_gateway import runtime_state


@pytest.fixture(autouse=True)
def _pid_file(tmp_path, monkeypatch):
    """Redirect the PID file to a temp location for every test."""
    path = tmp_path / "authmcp-gateway.pid"
    monkeypatch.setattr(runtime_state, "_PID_FILE", path, raising=False)
    return path


def test_read_pid_missing_returns_none():
    assert runtime_state.read_pid() is None


def test_write_and_read_pid(_pid_file):
    runtime_state.write_pid(4242)
    assert _pid_file.read_text(encoding="utf-8").strip() == "4242"
    assert runtime_state.read_pid() == 4242


def test_read_pid_invalid_content_returns_none(_pid_file):
    _pid_file.write_text("not-a-pid", encoding="utf-8")
    assert runtime_state.read_pid() is None


def test_clear_pid_is_idempotent(_pid_file):
    runtime_state.write_pid(1)
    runtime_state.clear_pid()
    assert not _pid_file.exists()
    # Second call must not raise.
    runtime_state.clear_pid()


def test_is_process_running_for_current_process():
    assert runtime_state.is_process_running(os.getpid()) is True


def test_is_process_running_rejects_invalid_pid():
    assert runtime_state.is_process_running(0) is False
    assert runtime_state.is_process_running(-5) is False


def test_get_running_pid_clears_stale_entry(_pid_file, monkeypatch):
    runtime_state.write_pid(999999)
    monkeypatch.setattr(runtime_state, "is_process_running", lambda _pid: False)

    assert runtime_state.get_running_pid() is None
    assert not _pid_file.exists()


def test_get_running_pid_returns_live_pid(_pid_file, monkeypatch):
    runtime_state.write_pid(1234)
    monkeypatch.setattr(runtime_state, "is_process_running", lambda _pid: True)

    assert runtime_state.get_running_pid() == 1234


def test_stop_process_returns_false_when_not_running(monkeypatch):
    monkeypatch.setattr(runtime_state, "is_process_running", lambda _pid: False)
    assert runtime_state.stop_process(4321) is False


def test_stop_process_signals_running_process(monkeypatch):
    monkeypatch.setattr(runtime_state, "is_process_running", lambda _pid: True)
    sent = {}
    monkeypatch.setattr(runtime_state.os, "kill", lambda pid, sig: sent.update({"pid": pid, "sig": sig}))

    assert runtime_state.stop_process(4321) is True
    assert sent["pid"] == 4321


def test_is_port_in_use_detects_listening_socket():
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        assert runtime_state.is_port_in_use("127.0.0.1", port) is True
    finally:
        server.close()

    # After close the port is free again.
    assert runtime_state.is_port_in_use("127.0.0.1", port) is False


def test_is_port_in_use_maps_wildcard_host():
    import socket

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    try:
        # 0.0.0.0 must be probed via 127.0.0.1.
        assert runtime_state.is_port_in_use("0.0.0.0", port) is True
    finally:
        server.close()


def test_wait_for_port_times_out_quickly(monkeypatch):
    monkeypatch.setattr(runtime_state, "is_port_in_use", lambda *a, **k: False)
    assert runtime_state.wait_for_port("127.0.0.1", 9, timeout=0.05, interval=0.01) is False


def test_wait_for_port_returns_true_when_open(monkeypatch):
    monkeypatch.setattr(runtime_state, "is_port_in_use", lambda *a, **k: True)
    assert runtime_state.wait_for_port("127.0.0.1", 9, timeout=1.0) is True

