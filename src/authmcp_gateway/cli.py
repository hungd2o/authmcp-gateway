"""CLI for AuthMCP Gateway."""

import argparse
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path

from authmcp_gateway import runtime_state


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="authmcp-gateway",
        description="Universal Authentication Gateway for MCP Servers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Start gateway with default config
  authmcp-gateway start

  # Start with custom config
  authmcp-gateway start --config /path/to/config.yaml

  # Start with environment variables
  authmcp-gateway start --env-file .env

  # Initialize database
  authmcp-gateway init-db

  # Create admin user
  authmcp-gateway create-admin --username admin --email admin@example.com

For more information, visit: https://github.com/loglux/authmcp-gateway
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Start command
    start_parser = subparsers.add_parser("start", help="Start the gateway server")
    start_parser.add_argument(
        "--host",
        default=None,
        help="Host to bind to (default: HOST env or 0.0.0.0)",
    )
    start_parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port to bind to (default: PORT env or 8000)",
    )
    start_parser.add_argument(
        "--config", type=Path, help="Path to configuration file (YAML or JSON)"
    )
    start_parser.add_argument(
        "--env-file", type=Path, default=".env", help="Path to .env file (default: .env)"
    )
    start_parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Logging level (default: LOG_LEVEL env or INFO)",
    )
    start_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    start_parser.add_argument(
        "--tray-icon",
        type=Path,
        default=None,
        metavar="ICON_PATH",
        help="Path to a custom .ico or .png file for the tray icon",
    )
    start_parser.add_argument(
        "--foreground",
        "-f",
        action="store_true",
        help="Run attached to this terminal and stream logs (tray Exit stops it)",
    )
    start_parser.add_argument(
        "--background",
        action="store_true",
        help=argparse.SUPPRESS,  # kept for backwards compatibility (now the default)
    )
    start_parser.add_argument(
        "--background-child",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    # Stop command
    subparsers.add_parser("stop", help="Stop the background gateway server")

    # Status command
    subparsers.add_parser("status", help="Show whether the gateway is running")

    # Init DB command
    init_parser = subparsers.add_parser("init-db", help="Initialize database")
    init_parser.add_argument(
        "--db-path",
        type=Path,
        default="data/auth.db",
        help="Path to SQLite database (default: data/auth.db)",
    )

    subparsers.add_parser(
        "init-whitelist-security",
        help="Create the Whitelist credential-encryption key in the local .env file",
    )

    # Create admin command
    admin_parser = subparsers.add_parser("create-admin", help="Create admin user")
    admin_parser.add_argument("--username", required=True, help="Admin username")
    admin_parser.add_argument("--email", required=True, help="Admin email")
    admin_parser.add_argument("--password", help="Admin password (will prompt if not provided)")
    admin_parser.add_argument(
        "--db-path",
        type=Path,
        default="data/auth.db",
        help="Path to SQLite database (default: data/auth.db)",
    )

    # Local break-glass recovery. No code-bearing arguments are accepted.
    recovery_parser = subparsers.add_parser("recover", help="Manage Whitelist recovery locally")
    recovery_parser.add_argument(
        "--db-path",
        type=Path,
        default="data/auth.db",
        help="Path to SQLite database (default: data/auth.db)",
    )

    # Version command
    subparsers.add_parser("version", help="Show version information")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Configure logging
    log_level = getattr(args, "log_level", None) or "INFO"
    logging.basicConfig(
        level=getattr(logging, log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if args.command == "start":
        start_server(args)
    elif args.command == "stop":
        stop_gateway(args)
    elif args.command == "status":
        gateway_status(args)
    elif args.command == "init-db":
        init_database(args)
    elif args.command == "init-whitelist-security":
        from authmcp_gateway.config import initialize_whitelist_credential_key

        initialize_whitelist_credential_key()
        print("✓ Whitelist credential-encryption key is ready in .env")
    elif args.command == "create-admin":
        create_admin_user(args)
    elif args.command == "recover":
        recover_whitelist_security(args)
    elif args.command == "version":
        show_version()


def start_server(args):
    """Start the AuthMCP Gateway.

    By default this launches the server + system tray in a detached background
    process and returns the terminal immediately.  Pass ``--foreground`` to run
    attached to the current terminal with streaming logs.
    """
    # Load environment variables
    if args.env_file and args.env_file.exists():
        from dotenv import load_dotenv

        load_dotenv(args.env_file)
        print(f"✓ Loaded environment from {args.env_file}")

    host = args.host or os.getenv("HOST", "0.0.0.0")
    port = args.port
    if port is None:
        try:
            port = int(os.getenv("PORT", "8000").strip())
        except ValueError:
            port = 8000
    log_level = args.log_level or os.getenv("LOG_LEVEL", "INFO").strip().upper()
    args.host = host
    args.port = port
    args.log_level = log_level

    # Set log level in environment
    os.environ["LOG_LEVEL"] = log_level

    # Display URL - show localhost instead of 0.0.0.0 for user convenience
    display_host = "localhost" if host == "0.0.0.0" else host
    server_url = f"http://{display_host}:{port}"

    is_worker = getattr(args, "background_child", False) or getattr(args, "foreground", False)

    if is_worker:
        _run_worker(args, server_url)
        return

    # Launcher path: spawn (or attach to) a detached background instance.
    existing_pid = runtime_state.get_running_pid()
    port_busy = runtime_state.is_port_in_use(host, port)

    if existing_pid is not None:
        # A managed instance is on record. Confirm it against the real port so a
        # crashed process that left the PID file behind does not look healthy.
        health = "listening" if port_busy else f"NOT responding on port {port}"
        print(
            "✓ AuthMCP Gateway is already running.\n"
            f"  URL: {server_url}\n"
            f"  PID: {existing_pid}\n"
            f"  Health: {health}\n"
            "  Use 'authmcp-gateway stop' to stop it, then start again.\n"
        )
        return

    if port_busy:
        # Port is taken but no managed PID on record: an unrelated process (or a
        # previous instance we can no longer control) owns it. Refuse to start a
        # second copy silently — surface it so runtime conflicts are visible.
        print(
            f"✗ Port {port} on {display_host} is already in use by another process.\n"
            "  AuthMCP Gateway did not start a second instance.\n"
            "  Free the port (or stop the other process) and try again.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # Nothing running and the port is free: drop any stale PID file and launch.
    runtime_state.clear_pid()

    from authmcp_gateway.tray import is_tray_available

    if not is_tray_available():
        print(
            "✗ System tray is required but not available.\n"
            "  Reinstall authmcp-gateway to restore bundled tray dependencies.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    _launch_background_server(args, server_url)


def _run_worker(args, server_url: str) -> None:
    """Run the server + system tray in this process and own the PID file."""
    import atexit

    print(f"""
╔══════════════════════════════════════════════════════════╗
║           AuthMCP Gateway                           ║
║   Universal Authentication for MCP Servers               ║
╚══════════════════════════════════════════════════════════╝

Starting server...
  URL: {server_url}
  Host: {args.host}
  Port: {args.port}
  Log Level: {args.log_level}
  Reload: {args.reload}
""")

    # Import app here to ensure environment is loaded first
    from authmcp_gateway.app import app
    from authmcp_gateway.config import get_config
    from authmcp_gateway.tray import is_tray_available

    runtime_config = get_config()
    if runtime_config.whitelist_token_generated and runtime_config.whitelist_token:
        print(
            "⚠ MCP_WHITELIST_TOKEN was not set. Generated temporary token for this run:\n"
            f"  {runtime_config.whitelist_token}\n"
            "  Open Admin > Whitelist and enter this token to approve pending items.\n"
        )

    if not is_tray_available():
        print(
            "✗ System tray is required but not available.\n"
            "  Reinstall authmcp-gateway to restore bundled tray dependencies.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    runtime_state.write_pid(os.getpid())
    atexit.register(runtime_state.clear_pid)
    try:
        _start_server_with_tray(app, args, runtime_config.whitelist_token)
    finally:
        runtime_state.clear_pid()


def _launch_background_server(args, server_url: str) -> None:
    """Relaunch the gateway in a detached child process."""
    log_file = _background_log_file_path()
    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)

    child_env = os.environ.copy()
    # Force UTF-8 stdio in the child: redirected to a file (no console), Python
    # falls back to the OS ANSI codepage (cp1252 on most Windows installs) for
    # print()'s encoding, which can't encode the ✓/⚠/✗ glyphs used in output
    # and crashes the child on its first print — before uvicorn/tray start.
    child_env["PYTHONIOENCODING"] = "utf-8"
    child_env["PYTHONUTF8"] = "1"

    log_stream = None
    try:
        if log_file is not None:
            log_stream = log_file.open("a", encoding="utf-8")

        process = subprocess.Popen(
            _build_background_start_command(args),
            cwd=os.getcwd(),
            env=child_env,
            stdin=subprocess.DEVNULL,
            stdout=log_stream if log_stream is not None else subprocess.DEVNULL,
            stderr=log_stream if log_stream is not None else subprocess.DEVNULL,
            start_new_session=_should_start_new_session(),
            creationflags=_windows_background_creationflags(),
        )
    except OSError as exc:
        print(f"✗ Failed to start AuthMCP Gateway in the background: {exc}")
        sys.exit(1)
    finally:
        if log_stream is not None:
            log_stream.close()

    # Record the child PID immediately as a short-lived launch lock so a second
    # invocation cannot spawn a duplicate before the worker binds the port.
    runtime_state.write_pid(process.pid)

    log_hint = (
        f"  Log file: {log_file}\n"
        if log_file is not None
        else "  Log file: disabled (set MCP_LOG_FILE_ENABLED=true and "
        "MCP_LOG_FILE=<path> to enable)\n"
    )

    # Verify the server actually came up instead of trusting the spawn alone, so
    # a worker that crashes on startup is reported rather than silently missing.
    if not runtime_state.wait_for_port(args.host, args.port):
        print(
            "✗ AuthMCP Gateway was launched but is not responding on "
            f"{args.host}:{args.port}.\n"
            f"  PID: {process.pid}\n"
            + log_hint
            + "  It may have failed to start — check the log file above "
            "(enable MCP_LOG_FILE for details) and run 'authmcp-gateway status'.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    # The worker records its own real PID once it starts; prefer it over the
    # spawn handle (which on Windows/uv can be an intermediate launcher PID).
    running_pid = runtime_state.get_running_pid() or process.pid

    print(
        "✓ AuthMCP Gateway is running in the background.\n"
        f"  URL: {server_url}\n"
        "  Mode: system tray\n"
        f"  PID: {running_pid}\n" + log_hint + "  Stop with: authmcp-gateway stop\n"
    )


def _get_background_executable() -> str:
    """Return the Python executable to use for the detached background child.

    On Windows the GUI-subsystem interpreter ``pythonw.exe`` is preferred over
    ``python.exe`` because it has no console window and remains fully
    associated with the desktop, which is a requirement for system-tray icons
    to initialise correctly.  Falls back to :data:`sys.executable` when
    ``pythonw.exe`` cannot be found (e.g. virtualenvs that only ship
    ``python.exe``).
    """
    if os.name != "nt":
        return sys.executable
    pythonw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
    return pythonw if os.path.isfile(pythonw) else sys.executable


def _build_background_start_command(args) -> list[str]:
    """Build the child process command for detached startup."""
    command = [
        _get_background_executable(),
        "-m",
        "authmcp_gateway.cli",
        "start",
        "--background-child",
    ]

    if args.host is not None:
        command.extend(["--host", args.host])
    if args.port is not None:
        command.extend(["--port", str(args.port)])
    if args.config is not None:
        command.extend(["--config", str(args.config)])
    if args.env_file is not None:
        command.extend(["--env-file", str(args.env_file)])
    if args.log_level is not None:
        command.extend(["--log-level", args.log_level])
    if args.reload:
        command.append("--reload")
    if getattr(args, "tray_icon", None):
        command.extend(["--tray-icon", str(args.tray_icon)])

    return command


def _env_bool(name: str, default: bool = False) -> bool:
    """Return a boolean parsed from environment variables."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _background_log_file_path() -> Path | None:
    """Return configured background log file path when explicitly enabled."""
    if not _env_bool("MCP_LOG_FILE_ENABLED", False):
        return None

    configured_path = os.getenv("MCP_LOG_FILE", "").strip()
    if not configured_path:
        return None
    return Path(configured_path).expanduser().resolve()


def _should_start_new_session() -> bool:
    """Return True when background mode should fully detach from the current session."""
    return os.name != "nt"


def _windows_background_creationflags() -> int:
    """Return process-creation flags for a background child on Windows.

    ``CREATE_NEW_PROCESS_GROUP`` isolates the child from Ctrl+C signals sent
    to the parent terminal so it continues running after the terminal closes.

    ``CREATE_NO_WINDOW`` suppresses any console window that ``python.exe``
    would otherwise open (harmless when ``pythonw.exe`` is used instead).

    ``DETACHED_PROCESS`` and ``CREATE_BREAKAWAY_FROM_JOB`` are intentionally
    omitted: ``DETACHED_PROCESS`` can prevent the Win32 message-loop required
    by system-tray icons from initialising, and ``CREATE_BREAKAWAY_FROM_JOB``
    raises ``PermissionError`` in many terminal environments that do not grant
    the breakaway privilege.
    """
    if os.name != "nt":
        return 0

    new_process_group = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
    create_no_window = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return new_process_group | create_no_window


def _start_server_with_tray(app, args, whitelist_token: str | None = None) -> None:
    """Run uvicorn in a background thread and the system tray on the main thread."""
    import threading

    import uvicorn

    from authmcp_gateway.tray import run_tray

    if args.reload:
        print(
            "⚠  --reload is not compatible with the system tray "
            "(uvicorn reloader requires the main thread).  Ignoring --reload.",
            file=sys.stderr,
        )

    config = uvicorn.Config(
        app,
        host=args.host,
        port=args.port,
        log_level=args.log_level.lower(),
    )
    server = uvicorn.Server(config)

    server_thread = threading.Thread(target=server.run, daemon=True, name="uvicorn-server")
    server_thread.start()

    display_host = "localhost" if args.host == "0.0.0.0" else args.host
    print(
        f"✓ AuthMCP Gateway is running in the system tray.\n"
        f"  Right-click the tray icon to open the dashboard or exit.\n"
        f"  Dashboard: http://{display_host}:{args.port}\n"
    )

    icon_path = str(args.tray_icon) if getattr(args, "tray_icon", None) else None

    # run_tray blocks until the user clicks Exit
    run_tray(
        port=args.port,
        host=args.host,
        server=server,
        icon_path=icon_path,
        whitelist_token=whitelist_token,
    )

    # Ensure uvicorn has stopped after the tray exits
    server.should_exit = True
    server_thread.join(timeout=10)


def stop_gateway(args):
    """Stop the background gateway server."""
    pid = runtime_state.get_running_pid()
    if pid is None:
        print("AuthMCP Gateway is not running.")
        return

    if runtime_state.stop_process(pid):
        runtime_state.clear_pid()
        print(f"✓ Stopped AuthMCP Gateway (PID {pid}).")
    else:
        print(f"✗ Failed to stop AuthMCP Gateway (PID {pid}).")
        sys.exit(1)


def gateway_status(args):
    """Report whether the gateway is currently running (PID + real port health)."""
    host = os.getenv("HOST", "0.0.0.0")
    try:
        port = int(os.getenv("PORT", "8000").strip())
    except ValueError:
        port = 8000
    display_host = "localhost" if host == "0.0.0.0" else host

    pid = runtime_state.get_running_pid()
    port_busy = runtime_state.is_port_in_use(host, port)

    if pid is None and not port_busy:
        print("AuthMCP Gateway is not running.")
        return

    if pid is not None:
        health = "listening" if port_busy else f"NOT responding on port {port}"
        print(
            f"AuthMCP Gateway is running (PID {pid}).\n"
            f"  URL: http://{display_host}:{port}\n"
            f"  Health: {health}"
        )
    else:
        # Port is taken but no PID on record: an unmanaged process owns it.
        print(
            f"Port {port} on {display_host} is in use, but no managed AuthMCP "
            "Gateway PID is on record (unmanaged or externally started process)."
        )


def init_database(args):
    """Initialize the SQLite database."""
    from authmcp_gateway.auth.oauth_code_flow import create_authorization_code_table
    from authmcp_gateway.auth.user_store import init_database as init_db
    from authmcp_gateway.auth.whitelist_store import init_whitelist_database

    db_path = str(args.db_path)

    # Create directory if it doesn't exist
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    print(f"Initializing database: {db_path}")

    try:
        init_db(db_path)
        create_authorization_code_table(db_path)
        init_whitelist_database(db_path)
        print("✓ Database initialized successfully")
    except (sqlite3.Error, OSError) as e:
        print(f"✗ Error initializing database: {e}")
        sys.exit(1)


def create_admin_user(args):
    """Create an admin user."""
    import getpass

    from authmcp_gateway.auth.password import hash_password
    from authmcp_gateway.auth.user_store import create_user, get_user_by_username

    db_path = str(args.db_path)

    # Check if database exists
    if not Path(db_path).exists():
        print(f"✗ Database not found: {db_path}")
        print("  Run 'authmcp-gateway init-db' first")
        sys.exit(1)

    # Check if user already exists
    existing_user = get_user_by_username(db_path, args.username)
    if existing_user:
        print(f"✗ User '{args.username}' already exists")
        sys.exit(1)

    # Get password
    if args.password:
        password = args.password
    else:
        password = getpass.getpass("Enter password: ")
        password_confirm = getpass.getpass("Confirm password: ")

        if password != password_confirm:
            print("✗ Passwords do not match")
            sys.exit(1)

    # Create user
    try:
        password_hash = hash_password(password)
        user_id = create_user(
            db_path=db_path,
            username=args.username,
            email=args.email,
            password_hash=password_hash,
            is_superuser=True,
        )
        print(f"✓ Admin user created successfully (ID: {user_id})")
        print(f"  Username: {args.username}")
        print(f"  Email: {args.email}")
    except (sqlite3.Error, ValueError) as e:
        print(f"✗ Error creating user: {e}")
        sys.exit(1)


def _recovery_user(db_path: str) -> tuple[int, str] | None:
    with sqlite3.connect(db_path) as connection:
        users = connection.execute(
            "SELECT id, username FROM users WHERE is_superuser = 1 ORDER BY username"
        ).fetchall()
    if not users:
        print("✗ No administrator account is available.", file=sys.stderr)
        return None
    for user_id, username in users:
        print(f"  {user_id}. {username}")
    try:
        selected = int(input("Select administrator ID: ").strip())
    except ValueError:
        print("✗ Invalid administrator selection.", file=sys.stderr)
        return None
    for user_id, username in users:
        if user_id == selected:
            return int(user_id), str(username)
    print("✗ Invalid administrator selection.", file=sys.stderr)
    return None


def _print_recovery_url(code: str) -> None:
    from urllib.parse import quote

    try:
        port = int(os.getenv("PORT", "8000").strip())
    except ValueError:
        port = 8000
    print(
        f"Recovery URL (expires in 5 minutes): http://localhost:{port}/whitelist/recover#code={quote(code)}"
    )


def recover_whitelist_security(args) -> None:
    """Run local, interactive break-glass operations without accepting a code as input."""
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("✗ The recover command requires interactive input and output TTYs.", file=sys.stderr)
        return
    db_path = str(args.db_path)
    if not Path(db_path).is_file():
        print("✗ Database not found. Run 'authmcp-gateway init-db' first.", file=sys.stderr)
        return
    from authmcp_gateway.auth import totp, whitelist_recovery, webauthn_store
    from authmcp_gateway.security.logger import log_security_event

    selected = _recovery_user(db_path)
    if selected is None:
        return
    user_id, username = selected
    print(
        "\n1. Restore browser access\n2. Register a new passkey\n3. Reset authenticator app\n4. Rotate recovery credential\n5. Show security status\n6. Cancel"
    )
    choice = input("Choose an action: ").strip()
    if choice in {"1", "2", "4"}:
        verb = "ROTATE" if choice == "4" else "CREATE"
        print(
            "This creates a one-time link that expires in five minutes and invalidates "
            "any previous unconsumed recovery link."
        )
        if input(f"Type {verb} to continue: ").strip() != verb:
            print("Recovery action cancelled.")
            return
        code = whitelist_recovery.create_recovery_code(db_path, user_id)
        _print_recovery_url(code)
        event = (
            "whitelist_recovery_code_rotated"
            if choice == "4"
            else "whitelist_recovery_code_created"
        )
        log_security_event(db_path, event, "high", user_id=user_id, username=username)
    elif choice == "3":
        print(
            f"This removes the authenticator app credential for {username}. "
            "It does not remove passkeys or approve any MCP item."
        )
        if input(f'Type "RESET {username}" to continue: ').strip() != f"RESET {username}":
            print("Authenticator reset cancelled.")
            return
        removed = totp.remove_totp(db_path, user_id)
        print("Authenticator removed." if removed else "No configured authenticator found.")
        log_security_event(
            db_path, "whitelist_totp_reset_local", "high", user_id=user_id, username=username
        )
    elif choice == "5":
        print(f"Passkeys: {len(webauthn_store.list_passkeys(db_path, user_id))}")
        print(
            f"Authenticator configured: {bool(totp.get_totp_credential(db_path, user_id, confirmed_only=True))}"
        )
        print(f"Recovery credential active: {whitelist_recovery.recovery_status(db_path, user_id)}")
        log_security_event(
            db_path, "whitelist_security_status_viewed", "low", user_id=user_id, username=username
        )
    elif choice != "6":
        print("✗ Invalid action.", file=sys.stderr)


def show_version():
    """Show version information."""
    try:
        from importlib.metadata import PackageNotFoundError, version

        pkg_version = version("authmcp-gateway")
    except PackageNotFoundError:
        try:
            from authmcp_gateway import __version__

            pkg_version = __version__
        except ImportError:
            pkg_version = "unknown"

    print(f"""
AuthMCP Gateway
Version: {pkg_version}
Python: {sys.version.split()[0]}

Homepage: https://github.com/loglux/authmcp-gateway
""")


if __name__ == "__main__":
    main()
