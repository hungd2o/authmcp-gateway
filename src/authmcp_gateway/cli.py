"""CLI for AuthMCP Gateway."""

import argparse
import logging
import os
import sqlite3
import subprocess
import sys
from pathlib import Path


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
        "--background",
        action="store_true",
        help="Start the gateway in the background and return the terminal immediately",
    )
    start_parser.add_argument(
        "--background-child",
        action="store_true",
        help=argparse.SUPPRESS,
    )

    # Init DB command
    init_parser = subparsers.add_parser("init-db", help="Initialize database")
    init_parser.add_argument(
        "--db-path",
        type=Path,
        default="data/auth.db",
        help="Path to SQLite database (default: data/auth.db)",
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
    elif args.command == "init-db":
        init_database(args)
    elif args.command == "create-admin":
        create_admin_user(args)
    elif args.command == "version":
        show_version()


def start_server(args):
    """Start the FastMCP Auth gateway server."""
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

    print(f"""
╔══════════════════════════════════════════════════════════╗
║           AuthMCP Gateway                           ║
║   Universal Authentication for MCP Servers               ║
╚══════════════════════════════════════════════════════════╝

Starting server...
  URL: {server_url}
  Host: {host}
  Port: {port}
  Log Level: {log_level}
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

    tray_available = is_tray_available()
    if not tray_available:
        print(
            "✗ System tray is required but not available.\n"
            "  Reinstall authmcp-gateway to restore bundled tray dependencies.\n",
            file=sys.stderr,
        )
        sys.exit(1)

    if _maybe_start_server_in_background(args, server_url):
        return

    _start_server_with_tray(app, args, runtime_config.whitelist_token)


def _maybe_start_server_in_background(args, server_url: str) -> bool:
    """Prompt for or honor background mode and relaunch if needed."""
    if getattr(args, "background_child", False):
        return False

    if getattr(args, "background", False):
        _launch_background_server(args, server_url)
        return True

    if not _supports_interactive_start_prompt():
        return False

    choice = _prompt_start_mode(args)
    if choice == "background":
        _launch_background_server(args, server_url)
        return True

    return False


def _supports_interactive_start_prompt() -> bool:
    """Return True when stdin/stdout are interactive TTYs."""
    stdin = getattr(sys, "stdin", None)
    stdout = getattr(sys, "stdout", None)
    return bool(
        stdin
        and stdout
        and hasattr(stdin, "isatty")
        and hasattr(stdout, "isatty")
        and stdin.isatty()
        and stdout.isatty()
    )


def _prompt_start_mode(args) -> str:
    """Prompt the user to keep logs attached or continue in the background."""
    if _background_log_file_path() is not None:
        background_label = "send to background (system tray + configured log file)"
    else:
        background_label = "send to background (system tray, no terminal logs)"

    prompt = (
        "\nChoose how to continue:\n"
        "  [1] View logs in this terminal (stdio)\n"
        f"  [2] {background_label}\n"
        "Select [1/2] (default: 1): "
    )

    while True:
        try:
            choice = input(prompt).strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nKeeping the gateway attached to this terminal.\n")
            return "foreground"

        if choice in ("", "1", "f", "fg", "foreground", "logs", "view", "view-logs"):
            return "foreground"
        if choice in ("2", "b", "bg", "background", "detach"):
            return "background"

        print("Please choose 1 to view logs or 2 to send the gateway to the background.\n")


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

    print(
        "✓ AuthMCP Gateway is running in the background.\n"
        f"  URL: {server_url}\n"
        "  Mode: system tray\n"
        f"  PID: {process.pid}\n"
        + (
            f"  Log file: {log_file}\n"
            if log_file is not None
            else "  Log file: disabled (set MCP_LOG_FILE_ENABLED=true and "
            "MCP_LOG_FILE=<path> to enable)\n"
        )
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


def init_database(args):
    """Initialize the SQLite database."""
    from authmcp_gateway.auth.oauth_code_flow import create_authorization_code_table
    from authmcp_gateway.auth.user_store import init_database as init_db

    db_path = str(args.db_path)

    # Create directory if it doesn't exist
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    print(f"Initializing database: {db_path}")

    try:
        init_db(db_path)
        create_authorization_code_table(db_path)
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
