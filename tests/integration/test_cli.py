"""Tests for the CLI entry point (`authmcp-gateway` command).

Covers argparse dispatch + each subcommand's happy and unhappy paths.
External side effects (uvicorn.run, getpass, dotenv, hash_password) are
mocked; the DB-touching tests use the real `initialized_db` fixture so
the SQLite schema and user creation paths are exercised end-to-end.
"""

import argparse
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from authmcp_gateway import cli


@pytest.fixture(autouse=True)
def _isolate_pid_file(tmp_path, monkeypatch):
    """Redirect the runtime PID file to a temp path so tests never touch data/."""
    monkeypatch.setattr(
        cli.runtime_state, "_PID_FILE", tmp_path / "authmcp-gateway.pid", raising=False
    )


# ---------------------------------------------------------------------------
# main() — argparse + dispatch
# ---------------------------------------------------------------------------


def test_main_no_command_prints_help_and_exits_1(capsys):
    """`authmcp-gateway` with no subcommand prints help and exits 1."""
    with patch.object(sys, "argv", ["authmcp-gateway"]):
        with pytest.raises(SystemExit) as exc_info:
            cli.main()
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "Available commands" in captured.out


def test_main_dispatches_to_start(monkeypatch):
    """`authmcp-gateway start` dispatches to start_server with parsed args."""
    called = {}

    def fake_start(args):
        called["host"] = args.host
        called["port"] = args.port

    monkeypatch.setattr(cli, "start_server", fake_start)
    monkeypatch.setattr(sys, "argv", ["authmcp-gateway", "start", "--port", "9000"])
    cli.main()
    assert called["host"] is None
    assert called["port"] == 9000


def test_main_dispatches_to_init_db(monkeypatch):
    called = {}
    monkeypatch.setattr(cli, "init_database", lambda args: called.setdefault("db", args.db_path))
    monkeypatch.setattr(sys, "argv", ["authmcp-gateway", "init-db", "--db-path", "/tmp/x.db"])
    cli.main()
    assert called["db"] == Path("/tmp/x.db")


def test_main_dispatches_to_create_admin(monkeypatch):
    called = {}
    monkeypatch.setattr(
        cli, "create_admin_user", lambda args: called.setdefault("user", args.username)
    )
    monkeypatch.setattr(
        sys,
        "argv",
        ["authmcp-gateway", "create-admin", "--username", "alice", "--email", "a@b.c"],
    )
    cli.main()
    assert called["user"] == "alice"


def test_main_dispatches_to_version(monkeypatch):
    called = {"hit": False}

    def fake_show():
        called["hit"] = True

    monkeypatch.setattr(cli, "show_version", fake_show)
    monkeypatch.setattr(sys, "argv", ["authmcp-gateway", "version"])
    cli.main()
    assert called["hit"]


def test_main_dispatches_to_stop(monkeypatch):
    called = {"hit": False}
    monkeypatch.setattr(cli, "stop_gateway", lambda args: called.update({"hit": True}))
    monkeypatch.setattr(sys, "argv", ["authmcp-gateway", "stop"])
    cli.main()
    assert called["hit"]


def test_main_dispatches_to_status(monkeypatch):
    called = {"hit": False}
    monkeypatch.setattr(cli, "gateway_status", lambda args: called.update({"hit": True}))
    monkeypatch.setattr(sys, "argv", ["authmcp-gateway", "status"])
    cli.main()
    assert called["hit"]


# ---------------------------------------------------------------------------
# stop / status
# ---------------------------------------------------------------------------


def test_stop_gateway_when_not_running(monkeypatch, capsys):
    """stop reports gracefully when no gateway is running."""
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: None)
    cli.stop_gateway(argparse.Namespace())
    assert "not running" in capsys.readouterr().out


def test_stop_gateway_signals_and_clears(monkeypatch, capsys):
    """stop signals the running process and clears the PID file."""
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 777)
    stopped = {}
    monkeypatch.setattr(cli.runtime_state, "stop_process", lambda pid: stopped.setdefault("pid", pid) or True)
    cleared = {"value": False}
    monkeypatch.setattr(cli.runtime_state, "clear_pid", lambda: cleared.update({"value": True}))

    cli.stop_gateway(argparse.Namespace())

    assert stopped == {"pid": 777}
    assert cleared == {"value": True}
    assert "Stopped" in capsys.readouterr().out


def test_stop_gateway_exits_on_failure(monkeypatch, capsys):
    """stop exits non-zero when the signal cannot be delivered."""
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 888)
    monkeypatch.setattr(cli.runtime_state, "stop_process", lambda pid: False)

    with pytest.raises(SystemExit) as exc_info:
        cli.stop_gateway(argparse.Namespace())

    assert exc_info.value.code == 1
    assert "Failed to stop" in capsys.readouterr().out


def test_gateway_status_running(monkeypatch, capsys):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 555)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: True)
    cli.gateway_status(argparse.Namespace())
    out = capsys.readouterr().out
    assert "running" in out
    assert "555" in out
    assert "listening" in out


def test_gateway_status_running_but_not_responding(monkeypatch, capsys):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 555)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: False)
    cli.gateway_status(argparse.Namespace())
    assert "NOT responding" in capsys.readouterr().out


def test_gateway_status_not_running(monkeypatch, capsys):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: None)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: False)
    cli.gateway_status(argparse.Namespace())
    assert "not running" in capsys.readouterr().out


def test_gateway_status_port_busy_unmanaged(monkeypatch, capsys):
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: None)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: True)
    cli.gateway_status(argparse.Namespace())
    assert "no managed" in capsys.readouterr().out.lower()


# ---------------------------------------------------------------------------
# start_server
# ---------------------------------------------------------------------------


def _start_args(tmp_path, **overrides):
    defaults = dict(
        host=None,
        port=None,
        config=None,
        env_file=tmp_path / "missing.env",
        log_level=None,
        reload=False,
        tray_icon=None,
        foreground=False,
        background=False,
        background_child=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_start_server_passes_args_to_tray_runner(tmp_path, monkeypatch, capsys):
    """start_server passes normalized args into tray startup."""
    fake_app_module = MagicMock()
    fake_app_module.app = "FAKE_APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: True)
    monkeypatch.setattr(cli.runtime_state, "write_pid", lambda _pid: None)
    monkeypatch.setattr(cli.runtime_state, "clear_pid", lambda: None)
    captured_call = {}
    monkeypatch.setattr(
        cli,
        "_start_server_with_tray",
        lambda app, args, whitelist_token=None: captured_call.update(
            {
                "app": app,
                "host": args.host,
                "port": args.port,
                "log_level": args.log_level,
                "reload": args.reload,
            }
        ),
    )

    args = _start_args(tmp_path, port=9090, log_level="DEBUG", reload=True, foreground=True)
    cli.start_server(args)

    assert captured_call == {
        "app": "FAKE_APP",
        "host": "0.0.0.0",
        "port": 9090,
        "log_level": "DEBUG",
        "reload": True,
    }
    captured = capsys.readouterr()
    assert "URL: http://localhost:9090" in captured.out  # 0.0.0.0 → localhost cosmetic


def test_start_server_uses_env_file_for_host_port_and_log_level(tmp_path, monkeypatch, capsys):
    """HOST/PORT/LOG_LEVEL from env file are used when CLI flags are omitted."""
    env_file = tmp_path / "real.env"
    env_file.write_text("HOST=127.0.0.1\nPORT=9105\nLOG_LEVEL=ERROR\n", encoding="utf-8")

    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: True)
    captured_call = {}
    monkeypatch.setattr(
        cli,
        "_start_server_with_tray",
        lambda app, args, whitelist_token=None: captured_call.update(
            {"app": app, "host": args.host, "port": args.port, "log_level": args.log_level}
        ),
    )
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    cli.start_server(_start_args(tmp_path, env_file=env_file, foreground=True))

    assert captured_call == {"app": "APP", "host": "127.0.0.1", "port": 9105, "log_level": "ERROR"}
    captured = capsys.readouterr()
    assert "URL: http://127.0.0.1:9105" in captured.out
    assert "Log Level: ERROR" in captured.out


def test_start_server_loads_existing_env_file(tmp_path, monkeypatch, capsys):
    """If --env-file points at a real file, dotenv.load_dotenv is called."""
    env_file = tmp_path / "real.env"
    env_file.write_text("DUMMY=1\n", encoding="utf-8")

    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: True)
    monkeypatch.setattr(
        cli, "_start_server_with_tray", lambda _app, _args, whitelist_token=None: None
    )
    fake_dotenv = MagicMock()
    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)

    args = _start_args(tmp_path, env_file=env_file, foreground=True)
    cli.start_server(args)

    fake_dotenv.load_dotenv.assert_called_once_with(env_file)
    captured = capsys.readouterr()
    assert "Loaded environment from" in captured.out


def test_start_server_sets_log_level_env(tmp_path, monkeypatch):
    """LOG_LEVEL gets set in the process env so subprocesses inherit it."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: True)
    monkeypatch.setattr(
        cli, "_start_server_with_tray", lambda _app, _args, whitelist_token=None: None
    )
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    cli.start_server(_start_args(tmp_path, log_level="WARNING", foreground=True))

    import os

    assert os.environ["LOG_LEVEL"] == "WARNING"


def test_start_server_foreground_flag_uses_tray(tmp_path, monkeypatch):
    """--foreground keeps logs attached and starts tray mode inline."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: True)
    monkeypatch.setattr(cli.runtime_state, "write_pid", lambda _pid: None)
    monkeypatch.setattr(cli.runtime_state, "clear_pid", lambda: None)
    tray_started = {"value": False}
    monkeypatch.setattr(
        cli,
        "_start_server_with_tray",
        lambda _app, _args, whitelist_token=None: tray_started.update({"value": True}),
    )

    cli.start_server(_start_args(tmp_path, foreground=True))

    assert tray_started == {"value": True}


def test_start_server_defaults_to_background(tmp_path, monkeypatch):
    """Running start with no flags spawns a detached background instance."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: True)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: None)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: False)
    monkeypatch.setattr(cli.runtime_state, "clear_pid", lambda: None)
    inline_started = {"value": False}
    monkeypatch.setattr(
        cli,
        "_start_server_with_tray",
        lambda _app, _args, whitelist_token=None: inline_started.update({"value": True}),
    )
    launched = {}
    monkeypatch.setattr(
        cli,
        "_launch_background_server",
        lambda args, server_url: launched.update({"server_url": server_url}),
    )

    cli.start_server(_start_args(tmp_path))

    assert launched == {"server_url": "http://localhost:8000"}
    assert inline_started == {"value": False}


def test_start_server_skips_launch_when_already_running(tmp_path, monkeypatch, capsys):
    """A second launch detects the running instance and does not spawn again."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 4321)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: True)
    launched = {"value": False}
    monkeypatch.setattr(
        cli,
        "_launch_background_server",
        lambda args, server_url: launched.update({"value": True}),
    )

    cli.start_server(_start_args(tmp_path))

    assert launched == {"value": False}
    out = capsys.readouterr().out
    assert "already running" in out
    assert "4321" in out


def test_start_server_reports_dead_pid_health(tmp_path, monkeypatch, capsys):
    """A recorded PID whose port is silent is reported as not responding."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 4321)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: False)
    monkeypatch.setattr(
        cli, "_launch_background_server", lambda args, server_url: pytest.fail("should not launch")
    )

    cli.start_server(_start_args(tmp_path))

    out = capsys.readouterr().out
    assert "NOT responding" in out


def test_start_server_exits_when_port_busy_and_unmanaged(tmp_path, monkeypatch, capsys):
    """Port taken by an unmanaged process aborts startup instead of spawning."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: None)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: True)
    monkeypatch.setattr(
        cli, "_launch_background_server", lambda args, server_url: pytest.fail("should not launch")
    )

    with pytest.raises(SystemExit) as exc_info:
        cli.start_server(_start_args(tmp_path))

    assert exc_info.value.code == 1
    err = capsys.readouterr().err
    assert "already in use" in err


def test_launch_background_server_reports_startup_failure(tmp_path, monkeypatch, capsys):
    """When the port never opens, the launcher reports failure and exits 1."""
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *a, **k: MagicMock(pid=9999))
    monkeypatch.setattr(cli.runtime_state, "write_pid", lambda _pid: None)
    monkeypatch.setattr(cli.runtime_state, "wait_for_port", lambda *a, **k: False)

    with pytest.raises(SystemExit) as exc_info:
        cli._launch_background_server(_start_args(tmp_path, host="127.0.0.1", port=9105), "http://127.0.0.1:9105")

    assert exc_info.value.code == 1
    assert "not responding" in capsys.readouterr().err


def test_launch_background_server_reports_real_worker_pid(tmp_path, monkeypatch, capsys):
    """On success the launcher reports the worker's real PID, not the spawn handle."""
    monkeypatch.setattr(cli.subprocess, "Popen", lambda *a, **k: MagicMock(pid=1111))
    monkeypatch.setattr(cli.runtime_state, "write_pid", lambda _pid: None)
    monkeypatch.setattr(cli.runtime_state, "wait_for_port", lambda *a, **k: True)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: 2222)

    cli._launch_background_server(
        _start_args(tmp_path, host="127.0.0.1", port=9105), "http://127.0.0.1:9105"
    )

    out = capsys.readouterr().out
    assert "PID: 2222" in out
    assert "1111" not in out


def test_start_server_exits_when_tray_unavailable(tmp_path, monkeypatch, capsys):
    """System tray is required and startup exits when tray deps are unavailable."""
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.setattr(cli.runtime_state, "get_running_pid", lambda: None)
    monkeypatch.setattr(cli.runtime_state, "is_port_in_use", lambda *a, **k: False)
    monkeypatch.setattr(cli.runtime_state, "clear_pid", lambda: None)
    monkeypatch.setattr("authmcp_gateway.tray.is_tray_available", lambda: False)

    with pytest.raises(SystemExit) as exc_info:
        cli.start_server(_start_args(tmp_path))

    assert exc_info.value.code == 1
    assert "System tray is required" in capsys.readouterr().err


def test_build_background_start_command_preserves_cli_flags(tmp_path):
    """Detached restart reuses the caller's explicit start flags."""
    args = _start_args(
        tmp_path,
        host="127.0.0.1",
        port=9105,
        config=tmp_path / "config.yaml",
        env_file=tmp_path / ".env",
        log_level="ERROR",
        reload=True,
        tray_icon=tmp_path / "icon.png",
    )

    command = cli._build_background_start_command(args)

    assert command == [
        cli._get_background_executable(),
        "-m",
        "authmcp_gateway.cli",
        "start",
        "--background-child",
        "--host",
        "127.0.0.1",
        "--port",
        "9105",
        "--config",
        str(tmp_path / "config.yaml"),
        "--env-file",
        str(tmp_path / ".env"),
        "--log-level",
        "ERROR",
        "--reload",
        "--tray-icon",
        str(tmp_path / "icon.png"),
    ]


def test_background_log_file_path_requires_enabled_flag_and_path(monkeypatch):
    """Background log file is disabled unless both env flag and path are set."""
    monkeypatch.delenv("MCP_LOG_FILE_ENABLED", raising=False)
    monkeypatch.delenv("MCP_LOG_FILE", raising=False)
    assert cli._background_log_file_path() is None

    monkeypatch.setenv("MCP_LOG_FILE_ENABLED", "true")
    assert cli._background_log_file_path() is None


def test_background_log_file_path_returns_resolved_path(monkeypatch, tmp_path):
    """Background log file path resolves when explicitly enabled and configured."""
    log_path = tmp_path / "gateway.log"
    monkeypatch.setenv("MCP_LOG_FILE_ENABLED", "1")
    monkeypatch.setenv("MCP_LOG_FILE", str(log_path))

    assert cli._background_log_file_path() == log_path.resolve()


def test_background_mode_starts_new_session_on_non_windows(monkeypatch):
    """Background mode detaches from current session on non-Windows."""
    monkeypatch.setattr(cli.os, "name", "posix")

    assert cli._should_start_new_session() is True


def test_background_mode_does_not_start_new_session_on_windows(monkeypatch):
    """Background mode on Windows uses creation flags instead of start_new_session."""
    monkeypatch.setattr(cli.os, "name", "nt")

    assert cli._should_start_new_session() is False


def test_windows_background_creationflags_uses_new_process_group_and_no_window(monkeypatch):
    """Windows background launch uses CREATE_NEW_PROCESS_GROUP and CREATE_NO_WINDOW.

    DETACHED_PROCESS is excluded because it prevents the Win32 message loop
    required by system-tray icons.  CREATE_BREAKAWAY_FROM_JOB is excluded
    because it raises PermissionError in terminals that disallow breakaway.
    """
    monkeypatch.setattr(cli.os, "name", "nt")
    monkeypatch.setattr(cli.subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200, raising=False)
    monkeypatch.setattr(cli.subprocess, "CREATE_NO_WINDOW", 0x08000000, raising=False)

    flags = cli._windows_background_creationflags()

    assert flags & 0x00000200, "CREATE_NEW_PROCESS_GROUP must be set"
    assert flags & 0x08000000, "CREATE_NO_WINDOW must be set"
    assert not (flags & 0x00000008), "DETACHED_PROCESS must NOT be set"
    assert not (flags & 0x01000000), "CREATE_BREAKAWAY_FROM_JOB must NOT be set"


def test_get_background_executable_returns_pythonw_when_present(monkeypatch, tmp_path):
    """On Windows, pythonw.exe is preferred over python.exe for tray support."""
    fake_python = tmp_path / "python.exe"
    fake_pythonw = tmp_path / "pythonw.exe"
    fake_python.touch()
    fake_pythonw.touch()

    monkeypatch.setattr(cli.os, "name", "nt")
    monkeypatch.setattr(cli.sys, "executable", str(fake_python))
    # os.path.isfile uses the real filesystem; both files exist in tmp_path.

    assert cli._get_background_executable() == str(fake_pythonw)


def test_get_background_executable_falls_back_when_pythonw_missing(monkeypatch, tmp_path):
    """Falls back to sys.executable when pythonw.exe is not alongside python.exe."""
    fake_python = tmp_path / "python.exe"
    fake_python.touch()

    monkeypatch.setattr(cli.os, "name", "nt")
    monkeypatch.setattr(cli.sys, "executable", str(fake_python))

    assert cli._get_background_executable() == str(fake_python)


def test_get_background_executable_returns_sys_executable_on_non_windows(monkeypatch):
    """On non-Windows platforms, sys.executable is returned unchanged."""
    monkeypatch.setattr(cli.os, "name", "posix")

    assert cli._get_background_executable() == sys.executable


# ---------------------------------------------------------------------------
# init_database
# ---------------------------------------------------------------------------


def test_init_database_creates_schema(tmp_path, capsys):
    """Real init creates the parent directory and writes the SQLite schema."""
    db_path = tmp_path / "nested" / "auth.db"
    args = argparse.Namespace(db_path=db_path)

    cli.init_database(args)

    assert db_path.exists()
    captured = capsys.readouterr()
    assert "Database initialized successfully" in captured.out

    # Sanity: a key table from user_store exists
    import sqlite3

    with sqlite3.connect(db_path) as conn:
        rows = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        ).fetchall()
    assert rows, "users table should exist after init"


def test_init_database_handles_sqlite_error(tmp_path, monkeypatch, capsys):
    """SQLite/OS errors print a friendly message and exit 1."""
    import sqlite3 as sqlite_mod

    monkeypatch.setattr(
        "authmcp_gateway.auth.user_store.init_database",
        lambda _: (_ for _ in ()).throw(sqlite_mod.OperationalError("db broken")),
    )
    args = argparse.Namespace(db_path=tmp_path / "x.db")

    with pytest.raises(SystemExit) as exc:
        cli.init_database(args)

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Error initializing database" in captured.out
    assert "db broken" in captured.out


# ---------------------------------------------------------------------------
# create_admin_user
# ---------------------------------------------------------------------------


def _admin_args(db_path, **overrides):
    defaults = dict(
        username="alice",
        email="alice@example.com",
        password=None,
        db_path=Path(db_path),
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_create_admin_aborts_if_db_missing(tmp_path, capsys):
    """Missing DB file -> exit 1 with 'init-db first' hint."""
    args = _admin_args(tmp_path / "nope.db", password="Pa$$w0rd!")

    with pytest.raises(SystemExit) as exc:
        cli.create_admin_user(args)

    assert exc.value.code == 1
    captured = capsys.readouterr()
    assert "Database not found" in captured.out
    assert "init-db" in captured.out


def test_create_admin_aborts_if_user_exists(initialized_db, capsys):
    """Pre-existing username -> exit 1."""
    from authmcp_gateway.auth.user_store import create_user

    create_user(initialized_db, "alice", "old@x.com", "hash")
    args = _admin_args(initialized_db, password="Pa$$w0rd!")

    with pytest.raises(SystemExit) as exc:
        cli.create_admin_user(args)

    assert exc.value.code == 1
    assert "already exists" in capsys.readouterr().out


def test_create_admin_password_mismatch_exits_1(initialized_db, monkeypatch, capsys):
    """Interactive password + confirmation mismatch -> exit 1."""
    answers = iter(["Pa$$w0rd!", "different!"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))

    args = _admin_args(initialized_db, password=None)

    with pytest.raises(SystemExit) as exc:
        cli.create_admin_user(args)

    assert exc.value.code == 1
    assert "Passwords do not match" in capsys.readouterr().out


def test_create_admin_happy_path_creates_superuser(initialized_db, capsys):
    """--password -> non-interactive create; user is_superuser=1."""
    args = _admin_args(initialized_db, password="Pa$$w0rd!")
    cli.create_admin_user(args)

    captured = capsys.readouterr()
    assert "Admin user created successfully" in captured.out

    from authmcp_gateway.auth.user_store import get_user_by_username

    user = get_user_by_username(initialized_db, "alice")
    assert user is not None
    assert user["is_superuser"] == 1
    assert user["email"] == "alice@example.com"


def test_create_admin_interactive_match_creates(initialized_db, monkeypatch, capsys):
    """Interactive password (matching confirmation) -> user created."""
    answers = iter(["Pa$$w0rd!", "Pa$$w0rd!"])
    monkeypatch.setattr("getpass.getpass", lambda _prompt: next(answers))

    args = _admin_args(initialized_db, password=None, username="bob", email="bob@b.com")
    cli.create_admin_user(args)

    assert "Admin user created successfully" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# show_version
# ---------------------------------------------------------------------------


def test_show_version_prints_installed_version(capsys):
    """show_version() prints the package version from importlib.metadata."""
    cli.show_version()
    captured = capsys.readouterr()
    assert "AuthMCP Gateway" in captured.out
    assert "Version:" in captured.out
    # Real install: should be the actual version string, not "unknown"
    assert "unknown" not in captured.out


def test_show_version_falls_back_when_package_not_found(monkeypatch, capsys):
    """If package metadata is missing, falls back to the source version."""
    from importlib.metadata import PackageNotFoundError

    from authmcp_gateway import __version__

    def boom(_name):
        raise PackageNotFoundError("authmcp-gateway")

    monkeypatch.setattr("importlib.metadata.version", boom)
    cli.show_version()
    captured = capsys.readouterr()
    assert f"Version: {__version__}" in captured.out
