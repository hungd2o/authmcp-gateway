"""CLI for AuthMCP Gateway."""

import argparse
import logging
import os
import sqlite3
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
        "--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)"
    )
    start_parser.add_argument(
        "--port", type=int, default=8000, help="Port to bind to (default: 8000)"
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
        default="INFO",
        help="Logging level (default: INFO)",
    )
    start_parser.add_argument(
        "--reload", action="store_true", help="Enable auto-reload for development"
    )
    start_parser.add_argument(
        "--no-tray",
        action="store_true",
        dest="no_tray",
        help=(
            "Disable the system tray icon and run in console-only mode. "
            "The tray is enabled by default when authmcp-gateway[tray] is installed."
        ),
    )
    start_parser.add_argument(
        "--tray-icon",
        type=Path,
        default=None,
        metavar="ICON_PATH",
        help="Path to a custom .ico or .png file for the tray icon",
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
    log_level = getattr(args, "log_level", "INFO")
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
    import uvicorn

    # Load environment variables
    if args.env_file and args.env_file.exists():
        from dotenv import load_dotenv

        load_dotenv(args.env_file)
        print(f"✓ Loaded environment from {args.env_file}")

    # Set log level in environment
    os.environ["LOG_LEVEL"] = args.log_level

    # Display URL - show localhost instead of 0.0.0.0 for user convenience
    display_host = "localhost" if args.host == "0.0.0.0" else args.host
    server_url = f"http://{display_host}:{args.port}"

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
    from authmcp_gateway.tray import is_tray_available

    no_tray = getattr(args, "no_tray", False)
    use_tray = (not no_tray) and is_tray_available()

    if use_tray:
        _start_server_with_tray(app, args)
    else:
        if not no_tray and not is_tray_available():
            print(
                "ℹ  System tray not available. "
                "Install authmcp-gateway[tray] to enable the tray icon.\n"
                "   Running in console mode — press CTRL+C to stop.\n",
                file=sys.stderr,
            )
        else:
            print("Press CTRL+C to stop\n")

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level=args.log_level.lower(),
            reload=args.reload,
        )


def _start_server_with_tray(app, args) -> None:
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
    run_tray(port=args.port, host=args.host, server=server, icon_path=icon_path)

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
        pkg_version = "unknown"

    print(f"""
AuthMCP Gateway
Version: {pkg_version}
Python: {sys.version.split()[0]}

Homepage: https://github.com/loglux/authmcp-gateway
""")


if __name__ == "__main__":
    main()
