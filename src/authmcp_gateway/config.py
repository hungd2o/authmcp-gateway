"""Configuration management for AuthMCP Gateway authentication."""

import os
import secrets
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Set
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def _env_bool(name: str, default: bool = False) -> bool:
    """Parse boolean from environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_list(name: str) -> List[str]:
    """Parse comma-separated list from environment variable."""
    value = os.getenv(name, "").strip()
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _env_set(name: str) -> Set[str]:
    """Parse comma-separated list into set from environment variable."""
    return set(_env_list(name))


def _env_int(name: str, default: int) -> int:
    """Parse integer from environment variable."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value.strip())
    except ValueError:
        return default


def _append_env_value(name: str, value: str) -> bool:
    """Persist a generated secret in an existing local ``.env`` file.

    The application must keep generated credential-encryption keys stable
    across restarts, but should not create a new configuration file solely for
    this setting. Existing values are never overwritten.
    """
    env_path = Path(".env")
    try:
        if env_path.exists():
            metadata = env_path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise OSError(".env must be a regular file, not a link")
            if os.name != "nt" and metadata.st_mode & 0o077:
                raise OSError(".env must not be readable by group or other users")
            open_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(env_path, open_flags)
            with os.fdopen(descriptor, "r", encoding="utf-8") as env_file:
                content = env_file.read()
        else:
            content = ""
        if any(line.strip().startswith(f"{name}=") for line in content.splitlines()):
            return True
        updated = content + ("\n" if content and not content.endswith("\n") else "") + f"{name}={value}\n"
        descriptor, temporary_name = tempfile.mkstemp(prefix=".env.", dir=".", text=True)
        try:
            if os.name != "nt":
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as env_file:
                env_file.write(updated)
                env_file.flush()
                os.fsync(env_file.fileno())
            os.replace(temporary_name, env_path)
            if os.name != "nt":
                directory = os.open(".", os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise
        return True
    except OSError as exc:
        print(f"\n⚠️  Warning: Could not persist {name} to .env: {exc}", file=sys.stderr)
        return False


def _read_env_value(name: str) -> Optional[str]:
    env_path = Path(".env")
    if not env_path.is_file():
        return None
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator and key.strip() == name:
                return value.strip() or None
    except OSError:
        return None
    return None


def initialize_whitelist_credential_key() -> str:
    """Create and persist the Whitelist encryption key on explicit request.

    Configuration loading must be read-only: silently creating a key during
    startup can make credentials unrecoverable when the local environment file
    is not the configuration source.  The CLI calls this deliberate bootstrap
    operation instead.
    """
    with _credential_key_lock():
        existing = os.getenv("WHITELIST_CREDENTIAL_ENCRYPTION_KEY") or _read_env_value(
            "WHITELIST_CREDENTIAL_ENCRYPTION_KEY"
        )
        key = (existing or Fernet.generate_key().decode("ascii")).strip()
        try:
            Fernet(key.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "WHITELIST_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key"
            ) from exc
        if not _append_env_value("WHITELIST_CREDENTIAL_ENCRYPTION_KEY", key):
            raise ValueError("Unable to persist WHITELIST_CREDENTIAL_ENCRYPTION_KEY to .env")
        return key


@contextmanager
def _credential_key_lock():
    """Serialize first-run key generation across independent worker processes."""
    lock_path = Path(".env.whitelist-credential-key.lock")
    deadline = time.monotonic() + 5
    with lock_path.open("a+b") as lock_file:
        while True:
            try:
                if os.name == "nt":
                    import msvcrt

                    lock_file.seek(0)
                    lock_file.write(b"0")
                    lock_file.flush()
                    lock_file.seek(0)
                    msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise ValueError(
                        "Timed out waiting to initialize WHITELIST_CREDENTIAL_ENCRYPTION_KEY"
                    )
                time.sleep(0.05)
        try:
            yield
        finally:
            if os.name == "nt":
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


@dataclass
class JWTConfig:
    """JWT token configuration."""

    algorithm: str  # HS256 or RS256
    secret_key: Optional[str] = None
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    access_token_expire_minutes: int = 30  # For MCP client access tokens
    refresh_token_expire_days: int = 7
    admin_token_expire_minutes: int = 480  # 8 hours for admin panel
    enforce_single_session: bool = True

    def __post_init__(self):
        """Validate JWT configuration."""
        if self.algorithm == "HS256":
            if not self.secret_key:
                # Auto-generate secret key
                self.secret_key = secrets.token_urlsafe(32)

                if not os.path.exists(".env"):
                    try:
                        if not _append_env_value("JWT_SECRET_KEY", self.secret_key):
                            raise OSError("secret persistence was refused")
                        print("\n" + "=" * 60, file=sys.stderr)
                        print("✓ Created .env file with generated JWT_SECRET_KEY", file=sys.stderr)
                        print("=" * 60 + "\n", file=sys.stderr)
                    except OSError as e:
                        print(f"\n⚠️  Warning: Could not create .env file: {e}", file=sys.stderr)
                        print(
                            "Please manually create .env with a JWT_SECRET_KEY.",
                            file=sys.stderr,
                        )
                        print(
                            "Run: python -c 'import secrets; "
                            'print("JWT_SECRET_KEY=" + secrets.token_urlsafe(32))\' >> .env\n',
                            file=sys.stderr,
                        )
                else:
                    _append_env_value("JWT_SECRET_KEY", self.secret_key)
                    # .env exists but no JWT_SECRET_KEY - show warning
                    print("\n" + "=" * 60, file=sys.stderr)
                    print("⚠️  WARNING: Auto-generated JWT_SECRET_KEY", file=sys.stderr)
                    print("=" * 60, file=sys.stderr)
                    print("A random JWT secret key was generated automatically.", file=sys.stderr)
                    print(
                        "\nFor PRODUCTION use, add a persistent JWT_SECRET_KEY to .env.",
                        file=sys.stderr,
                    )
                    print(
                        "Generate one with: python -c 'import secrets; "
                        "print(secrets.token_urlsafe(32))'",
                        file=sys.stderr,
                    )
                    print(
                        "\nWithout a persistent key, all tokens will be invalidated",
                        file=sys.stderr,
                    )
                    print("on server restart!", file=sys.stderr)
                    print("=" * 60 + "\n", file=sys.stderr)
        elif self.algorithm == "RS256":
            if not self.private_key or not self.public_key:
                raise ValueError(
                    "JWT_PRIVATE_KEY and JWT_PUBLIC_KEY are required when using RS256 algorithm"
                )
        else:
            raise ValueError(f"Unsupported JWT algorithm: {self.algorithm}. Use HS256 or RS256.")


@dataclass
class AuthConfig:
    """Authentication and password policy configuration."""

    allow_registration: bool = False
    allow_dcr: bool = False
    dcr_require_initial_token: bool = False
    dcr_initial_access_token: Optional[str] = None
    sqlite_path: str = "data/auth.db"
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digit: bool = True
    password_require_special: bool = True
    # OAuth scope allowlist — requests for any scope outside this set are rejected
    # at /authorize and /oauth/register. The default mirrors the OIDC scopes the
    # gateway can actually fulfil today; extend via AUTH_ALLOWED_SCOPES env.
    allowed_scopes: Set[str] = field(
        default_factory=lambda: {"openid", "profile", "email", "offline_access"}
    )


@dataclass
class RateLimitConfig:
    """Rate limiting configuration."""

    enabled: bool = True
    login_limit: int = 5  # Max login attempts
    login_window: int = 60  # Seconds
    register_limit: int = 3  # Max registrations
    register_window: int = 300  # 5 minutes
    dcr_limit: int = 10  # Max dynamic client registrations
    dcr_window: int = 3600  # 1 hour
    mcp_limit: int = 100  # Max MCP requests per user per window
    mcp_window: int = 60  # Seconds
    cleanup_interval: int = 3600  # Cleanup old entries every hour


@dataclass
class WhitelistAuthConfig:
    """Whitelist second-factor session configuration (passkey/TOTP layer)."""

    session_minutes: int = 15
    passkey_fresh_seconds: int = 120
    webauthn_rp_ids: List[str] = field(default_factory=list)
    webauthn_allowed_origins: List[str] = field(default_factory=list)
    credential_encryption_key: Optional[str] = None

    def __post_init__(self):
        if self.session_minutes <= 0 or self.session_minutes > 120:
            raise ValueError("WHITELIST_SESSION_MINUTES must be between 1 and 120")
        if self.passkey_fresh_seconds <= 0 or self.passkey_fresh_seconds > 600:
            raise ValueError("WHITELIST_PASSKEY_FRESH_SECONDS must be between 1 and 600")
        for origin in self.webauthn_allowed_origins:
            parsed = urlsplit(origin)
            try:
                port = parsed.port
            except ValueError as exc:
                raise ValueError("WEBAUTHN_ALLOWED_ORIGINS contains an invalid port") from exc
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or port is not None
                and not 1 <= port <= 65535
                or parsed.path
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                raise ValueError(
                    "WEBAUTHN_ALLOWED_ORIGINS values must be complete origins, for example "
                    "https://admin.example.com"
                )
        if not self.credential_encryption_key:
            return
        try:
            Fernet(self.credential_encryption_key.encode("ascii"))
        except (TypeError, ValueError) as exc:
            raise ValueError(
                "WHITELIST_CREDENTIAL_ENCRYPTION_KEY must be a valid Fernet key"
            ) from exc


@dataclass
class AppConfig:
    """Complete application configuration."""

    # JWT settings
    jwt: JWTConfig

    # Auth settings
    auth: AuthConfig

    # Rate limiting settings
    rate_limit: RateLimitConfig

    # MCP public URL
    mcp_public_url: str

    # Authentication enforcement
    auth_required: bool = True

    # Static bearer tokens (for backward compatibility or service accounts)
    static_bearer_tokens: List[str] = field(default_factory=list)

    # Trusted IPs (bypass auth for local services)
    trusted_ips: Set[str] = field(default_factory=set)

    # RAG backend configuration
    rag_api_base_url: str = "http://localhost:8004/api/v1"
    rag_api_bearer: Optional[str] = None
    rag_api_key: Optional[str] = None
    rag_api_username: Optional[str] = None
    rag_api_password: Optional[str] = None

    # Default knowledge base
    default_kb_id: Optional[str] = None

    # Network settings
    request_timeout_seconds: int = 60
    allow_insecure_http: bool = False
    allowed_origins: Set[str] = field(default_factory=set)
    disable_dns_rebinding: bool = True
    transport_allowed_hosts: List[str] = field(default_factory=list)
    transport_allowed_origins: List[str] = field(default_factory=list)

    # Retrieval config
    retrieval_config_path: Optional[str] = None
    retrieval_config_ttl_seconds: float = 2.0

    # Logging
    log_level: str = "INFO"
    # NOTE: Optional DB logging for MCP requests (kept for future internal storage)
    mcp_log_db_enabled: bool = True
    # Optional archive of old DB logs to file before cleanup
    mcp_log_db_archive_enabled: bool = False
    mcp_log_db_archive_path: Optional[str] = None
    # DB log retention and size/row limits
    mcp_log_db_days_to_keep: int = 30
    mcp_log_db_max_mb: int = 200
    mcp_log_db_max_rows: int = 200000
    mcp_log_db_check_interval_seconds: int = 300
    mgmt_audit_days_to_keep: int = 90
    mgmt_audit_max_mb: int = 200
    mgmt_audit_max_rows: int = 200000
    mgmt_audit_archive_enabled: bool = True
    mgmt_audit_archive_path: Optional[str] = "data/management-audit.jsonl"
    whitelist_token: Optional[str] = None
    whitelist_token_generated: bool = False
    whitelist_auth: WhitelistAuthConfig = field(default_factory=WhitelistAuthConfig)

    def __post_init__(self) -> None:
        """Derive WebAuthn defaults from the configured canonical public URL."""
        parsed = urlsplit(self.mcp_public_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.netloc:
            return
        if not self.whitelist_auth.webauthn_rp_ids:
            self.whitelist_auth.webauthn_rp_ids = [parsed.hostname.lower()]
        if not self.whitelist_auth.webauthn_allowed_origins:
            self.whitelist_auth.webauthn_allowed_origins = [
                f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"
            ]

    @property
    def retrieval_config_ttl(self) -> float:
        """Alias for retrieval_config_ttl_seconds for backward compatibility."""
        return self.retrieval_config_ttl_seconds


def _load_jwt_keys(
    algorithm: str, private_key_path: Optional[str], public_key_path: Optional[str]
) -> tuple[Optional[str], Optional[str]]:
    """Load RSA keys from file paths if using RS256."""
    if algorithm != "RS256":
        return None, None

    private_key = None
    public_key = None

    if private_key_path:
        try:
            with open(private_key_path, "r", encoding="utf-8") as f:
                private_key = f.read()
        except FileNotFoundError:
            raise ValueError(f"Private key file not found: {private_key_path}")
        except OSError as e:
            raise ValueError(f"Failed to read private key from {private_key_path}: {e}")

    if public_key_path:
        try:
            with open(public_key_path, "r", encoding="utf-8") as f:
                public_key = f.read()
        except FileNotFoundError:
            raise ValueError(f"Public key file not found: {public_key_path}")
        except OSError as e:
            raise ValueError(f"Failed to read public key from {public_key_path}: {e}")

    return private_key, public_key


def load_config() -> AppConfig:
    """Load configuration from environment variables.

    Returns:
        AppConfig: Complete application configuration

    Raises:
        ValueError: If required configuration is missing or invalid
    """
    # JWT Configuration
    jwt_algorithm = os.getenv("JWT_ALGORITHM", "HS256").strip().upper()
    jwt_secret_key = os.getenv("JWT_SECRET_KEY", "").strip() or None

    # Load RSA keys from file paths if RS256
    jwt_private_key_path = os.getenv("JWT_PRIVATE_KEY_PATH", "").strip() or None
    jwt_public_key_path = os.getenv("JWT_PUBLIC_KEY_PATH", "").strip() or None

    jwt_private_key, jwt_public_key = _load_jwt_keys(
        jwt_algorithm, jwt_private_key_path, jwt_public_key_path
    )

    jwt_config = JWTConfig(
        algorithm=jwt_algorithm,
        secret_key=jwt_secret_key,
        private_key=jwt_private_key,
        public_key=jwt_public_key,
        access_token_expire_minutes=_env_int(
            "JWT_ACCESS_TOKEN_EXPIRE_MINUTES", 10080
        ),  # 7 days for MCP clients
        refresh_token_expire_days=_env_int("JWT_REFRESH_TOKEN_EXPIRE_DAYS", 7),
        admin_token_expire_minutes=_env_int(
            "ADMIN_TOKEN_EXPIRE_MINUTES", 480
        ),  # 8 hours for admin panel
        enforce_single_session=_env_bool("JWT_ENFORCE_SINGLE_SESSION", True),
    )

    # Auth Configuration
    # AUTH_ALLOWED_SCOPES accepts space- or comma-separated scope tokens
    # (e.g. "openid profile email" or "openid,profile,email").
    from .utils import _parse_scopes

    allowed_scopes_env = set(_parse_scopes(os.getenv("AUTH_ALLOWED_SCOPES", "")))
    auth_config = AuthConfig(
        allow_registration=_env_bool("ALLOW_REGISTRATION", False),
        allow_dcr=_env_bool("ALLOW_DCR", False),
        dcr_require_initial_token=_env_bool("DCR_REQUIRE_INITIAL_TOKEN", False),
        dcr_initial_access_token=os.getenv("DCR_INITIAL_ACCESS_TOKEN", "").strip() or None,
        sqlite_path=os.getenv("AUTH_SQLITE_PATH", "data/auth.db"),
        password_min_length=_env_int("PASSWORD_MIN_LENGTH", 8),
        password_require_uppercase=_env_bool("PASSWORD_REQUIRE_UPPERCASE", True),
        password_require_lowercase=_env_bool("PASSWORD_REQUIRE_LOWERCASE", True),
        password_require_digit=_env_bool("PASSWORD_REQUIRE_DIGIT", True),
        password_require_special=_env_bool("PASSWORD_REQUIRE_SPECIAL", True),
        **({"allowed_scopes": allowed_scopes_env} if allowed_scopes_env else {}),
    )

    # Rate Limiting Configuration
    rate_limit_config = RateLimitConfig(
        enabled=_env_bool("RATE_LIMIT_ENABLED", True),
        login_limit=_env_int("RATE_LIMIT_LOGIN_MAX", 5),
        login_window=_env_int("RATE_LIMIT_LOGIN_WINDOW", 60),
        register_limit=_env_int("RATE_LIMIT_REGISTER_MAX", 3),
        register_window=_env_int("RATE_LIMIT_REGISTER_WINDOW", 300),
        dcr_limit=_env_int("RATE_LIMIT_DCR_MAX", 10),
        dcr_window=_env_int("RATE_LIMIT_DCR_WINDOW", 3600),
        mcp_limit=_env_int("RATE_LIMIT_MCP_MAX", 100),
        mcp_window=_env_int("RATE_LIMIT_MCP_WINDOW", 60),
        cleanup_interval=_env_int("RATE_LIMIT_CLEANUP_INTERVAL", 3600),
    )

    # Application Configuration
    mcp_public_url = os.getenv("MCP_PUBLIC_URL", "http://localhost:8000").rstrip("/")

    app_config = AppConfig(
        jwt=jwt_config,
        auth=auth_config,
        rate_limit=rate_limit_config,
        mcp_public_url=mcp_public_url,
        auth_required=_env_bool("AUTH_REQUIRED", True),
        static_bearer_tokens=_env_list("STATIC_BEARER_TOKENS"),
        trusted_ips=_env_set("MCP_TRUSTED_IPS"),
        rag_api_base_url=os.getenv("RAG_API_BASE_URL", "http://localhost:8004/api/v1").rstrip("/"),
        rag_api_bearer=os.getenv("RAG_API_BEARER", "").strip() or None,
        rag_api_key=os.getenv("RAG_API_KEY", "").strip() or None,
        rag_api_username=os.getenv("RAG_API_USERNAME", "").strip() or None,
        rag_api_password=os.getenv("RAG_API_PASSWORD", "").strip() or None,
        default_kb_id=os.getenv("DEFAULT_KB_ID", "").strip() or None,
        request_timeout_seconds=_env_int("REQUEST_TIMEOUT_SECONDS", 60),
        allow_insecure_http=_env_bool("ALLOW_INSECURE_HTTP", False),
        allowed_origins=_env_set("ALLOWED_ORIGINS"),
        disable_dns_rebinding=_env_bool("DISABLE_DNS_REBINDING", True),
        transport_allowed_hosts=_env_list("TRANSPORT_ALLOWED_HOSTS"),
        transport_allowed_origins=_env_list("TRANSPORT_ALLOWED_ORIGINS"),
        retrieval_config_path=os.getenv("RETRIEVAL_CONFIG_PATH", "").strip() or None,
        retrieval_config_ttl_seconds=float(os.getenv("RETRIEVAL_CONFIG_TTL_SECONDS", "2.0")),
        log_level=os.getenv("LOG_LEVEL", "INFO").upper(),
        mcp_log_db_enabled=_env_bool("MCP_LOG_DB_ENABLED", True),
        mcp_log_db_archive_enabled=_env_bool("MCP_LOG_DB_ARCHIVE_ENABLED", False),
        mcp_log_db_archive_path=os.getenv("MCP_LOG_DB_ARCHIVE_PATH", "").strip() or None,
        mcp_log_db_days_to_keep=_env_int("MCP_LOG_DB_DAYS_TO_KEEP", 30),
        mcp_log_db_max_mb=_env_int("MCP_LOG_DB_MAX_MB", 200),
        mcp_log_db_max_rows=_env_int("MCP_LOG_DB_MAX_ROWS", 200000),
        mcp_log_db_check_interval_seconds=_env_int("MCP_LOG_DB_CHECK_INTERVAL_SECONDS", 300),
        mgmt_audit_days_to_keep=_env_int("MGMT_AUDIT_DAYS_TO_KEEP", 90),
        mgmt_audit_max_mb=_env_int("MGMT_AUDIT_MAX_MB", 200),
        mgmt_audit_max_rows=_env_int("MGMT_AUDIT_MAX_ROWS", 200000),
        mgmt_audit_archive_enabled=_env_bool("MGMT_AUDIT_ARCHIVE_ENABLED", True),
        mgmt_audit_archive_path=(
            os.getenv("MGMT_AUDIT_ARCHIVE_PATH", "data/management-audit.jsonl").strip() or None
        ),
        whitelist_token=os.getenv("MCP_WHITELIST_TOKEN", "").strip() or None,
        whitelist_auth=WhitelistAuthConfig(
            session_minutes=_env_int("WHITELIST_SESSION_MINUTES", 15),
            passkey_fresh_seconds=_env_int("WHITELIST_PASSKEY_FRESH_SECONDS", 120),
            webauthn_rp_ids=_env_list("WEBAUTHN_RP_IDS"),
            webauthn_allowed_origins=_env_list("WEBAUTHN_ALLOWED_ORIGINS"),
            credential_encryption_key=os.getenv("WHITELIST_CREDENTIAL_ENCRYPTION_KEY", "").strip()
            or None,
        ),
    )

    return app_config


# Global config instance (loaded once on import)
_config_instance: Optional[AppConfig] = None


def get_config() -> AppConfig:
    """Get the global configuration instance.

    Returns:
        AppConfig: The application configuration
    """
    global _config_instance
    if _config_instance is None:
        _config_instance = load_config()
    return _config_instance
