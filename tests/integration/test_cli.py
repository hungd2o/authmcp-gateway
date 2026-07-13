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
        no_tray=True,
        tray_icon=None,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def test_start_server_passes_args_to_uvicorn(tmp_path, monkeypatch, capsys):
    """uvicorn.run gets host/port/log_level/reload from args."""
    fake_uvicorn = MagicMock()
    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    # Don't actually load the real app — substitute a sentinel.
    fake_app_module = MagicMock()
    fake_app_module.app = "FAKE_APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)

    args = _start_args(tmp_path, port=9090, log_level="DEBUG", reload=True)
    cli.start_server(args)

    fake_uvicorn.run.assert_called_once_with(
        "FAKE_APP", host="0.0.0.0", port=9090, log_level="debug", reload=True
    )
    captured = capsys.readouterr()
    assert "URL: http://localhost:9090" in captured.out  # 0.0.0.0 → localhost cosmetic


def test_start_server_uses_env_file_for_host_port_and_log_level(tmp_path, monkeypatch, capsys):
    """HOST/PORT/LOG_LEVEL from env file are used when CLI flags are omitted."""
    env_file = tmp_path / "real.env"
    env_file.write_text("HOST=127.0.0.1\nPORT=9105\nLOG_LEVEL=ERROR\n", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "uvicorn", MagicMock())
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("HOST", raising=False)
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    cli.start_server(_start_args(tmp_path, env_file=env_file))

    sys.modules["uvicorn"].run.assert_called_once_with(
        "APP", host="127.0.0.1", port=9105, log_level="error", reload=False
    )
    captured = capsys.readouterr()
    assert "URL: http://127.0.0.1:9105" in captured.out
    assert "Log Level: ERROR" in captured.out


def test_start_server_loads_existing_env_file(tmp_path, monkeypatch, capsys):
    """If --env-file points at a real file, dotenv.load_dotenv is called."""
    env_file = tmp_path / "real.env"
    env_file.write_text("DUMMY=1\n", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "uvicorn", MagicMock())
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    fake_dotenv = MagicMock()
    monkeypatch.setitem(sys.modules, "dotenv", fake_dotenv)

    args = _start_args(tmp_path, env_file=env_file)
    cli.start_server(args)

    fake_dotenv.load_dotenv.assert_called_once_with(env_file)
    captured = capsys.readouterr()
    assert "Loaded environment from" in captured.out


def test_start_server_sets_log_level_env(tmp_path, monkeypatch):
    """LOG_LEVEL gets set in the process env so subprocesses inherit it."""
    monkeypatch.setitem(sys.modules, "uvicorn", MagicMock())
    fake_app_module = MagicMock()
    fake_app_module.app = "APP"
    monkeypatch.setitem(sys.modules, "authmcp_gateway.app", fake_app_module)
    monkeypatch.delenv("LOG_LEVEL", raising=False)

    cli.start_server(_start_args(tmp_path, log_level="WARNING"))

    import os

    assert os.environ["LOG_LEVEL"] == "WARNING"


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
    """If importlib.metadata raises PackageNotFoundError, prints 'unknown'."""
    from importlib.metadata import PackageNotFoundError

    def boom(_name):
        raise PackageNotFoundError("authmcp-gateway")

    monkeypatch.setattr("importlib.metadata.version", boom)
    cli.show_version()
    captured = capsys.readouterr()
    assert "Version: unknown" in captured.out
