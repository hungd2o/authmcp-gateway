# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.54] - 2026-05-09

### Changed
- mypy cleanup: cleared all 21 errors in `security/mcp_auditor.py`.
- All 21 errors were a single inference issue: each test method built
  a `result = {...}` dict in multiple branches with mixed value types
  ("details" being `dict | None`, "message" being `str | None`).
  mypy locked in the dict shape from the first branch and rejected
  every later branch with a wider value type, then propagated that
  into the `self.results.append((status, name, message))` tuple-shape
  check.
- Fixed by adding `result: Dict[str, Any]` annotations before the
  first dict literal in each of the six test methods. This is the
  only change in the file — no behaviour difference.

### Notes
- mypy: 102 -> 81 errors. 184 tests pass.
- Same one-line annotation pattern likely fixes a chunk of the
  remaining offenders (`security/logger.py`, `admin/user_pages.py`,
  `mcp/handler.py`).

## [1.2.53] - 2026-05-09

### Changed
- mypy cleanup: cleared all 19 errors in `mcp/proxy.py`.
- Real bugs caught and fixed:
  - 3× `asyncio.gather(return_exceptions=True)` callsites in
    `get_aggregated_capabilities`, `list_tools`, `list_resources`,
    `list_prompts` were filtering with `isinstance(result, Exception)`
    — but `gather` returns `T | BaseException`, so KeyboardInterrupt
    / SystemExit / CancelledError would have leaked into `.items()`,
    `.extend()` and the formatter. Switched to
    `isinstance(result, BaseException)` so the type narrows correctly
    and these never escape into downstream "iterate / merge" code.
  - `read_resource` was annotated `-> Dict[str, Any]` but actually
    returned `Tuple[Dict[str, Any], Dict[str, Any]]` (response, server)
    — its single caller in `mcp/handler.py` already unpacked the tuple.
    Fixed annotation.
  - `_proxy_jsonrpc` 401-retry path overwrote `server` with the result
    of `get_mcp_server(...)` which can return `None`. Added explicit
    None check that aborts the retry instead of dereferencing None.
- `[no-any-return]` pulls cast to declared shapes via `typing.cast`
  (parse_sse_response, fetch tools / resources / prompts /
  resource templates, capabilities discovery, idempotency check).
- `[var-annotated]` locals annotated explicitly:
  - `caps: Dict[str, Any]`
  - `all_tools / all_resources / all_prompts: List[Dict[str, Any]]`
  - `result_keys: Union[List[Any], str]` (the diagnostic log line
    that holds either dict keys or "N/A").

### Notes
- No behaviour change. 184 tests pass.
- mypy: 131 -> 102 errors (proxy.py + downstream caller errors that
  the corrected `read_resource` signature also resolved).

## [1.2.52] - 2026-05-09

### Changed
- mypy cleanup (start of campaign): cleaned all 4 mypy errors in
  `auth/jwt_handler.py` — the foundational JWT module that every
  request flows through.
- 3× implicit Optional defaults made explicit:
  - `create_access_token(expire_minutes: int = None)` ->
    `expire_minutes: int | None = None`.
  - `create_refresh_token(expire_days: int = None)` ->
    `expire_days: int | None = None`.
  - `create_id_token(expire_minutes: int = None)` ->
    `expire_minutes: int | None = None`.
  PEP 484 prohibits implicit Optional and recent mypy enforces it.
- 1× `[no-any-return]`: `get_token_jti` was declared to return `str`
  but pulled out of a `dict[str, Any]`. Now wrapped in
  `typing.cast(str, payload["jti"])` to express that the JWT spec
  guarantees JTI is a string.

### Notes
- No behaviour change. 184 tests pass.
- mypy: 135 -> 131 errors. Per-release cleanup continues.

## [1.2.51] - 2026-05-09

### Changed
- Audit (A1 final batch): narrowed the last 6 broad `except Exception`
  clauses in the CLI surface and the setup wizard. Concludes the
  except-narrowing campaign that started in 1.2.35.
- `cli.py`:
  - `init-db` subcommand catch -> `(sqlite3.Error, OSError)`. Covers
    DB connection / schema-creation errors and missing parent dirs.
  - `create-admin` subcommand catch -> `(sqlite3.Error, ValueError)`.
    Covers DB errors and bcrypt's "password too long" `ValueError`.
  - `version` subcommand catch -> `PackageNotFoundError`. Stops
    masking unrelated import failures as "version: unknown".
- `setup_wizard.py`:
  - `is_setup_required` user-count probe -> `(sqlite3.Error, OSError)`.
    "DB doesn't exist yet" and real DB errors stay handled; a logic
    bug in `get_all_users` no longer silently triggers the setup flow.
  - Inline password-policy override (best-effort) ->
    `(RuntimeError, AttributeError, TypeError, KeyError)`. The block
    is intentionally permissive — it falls back to env-config policy
    on any failure — but stops eating MemoryError / SystemExit etc.
  - Top-level `create_admin_user` handler ->
    `(sqlite3.Error, ValueError, json.JSONDecodeError, TypeError,
    KeyError)`. Covers the request body parse + DB write paths.

### Notes
- No behaviour change on the happy path. 184 tests pass.
- A1 audit campaign complete: 100+ broad excepts narrowed across 17
  files / 17 releases (1.2.35–1.2.51). Remaining broad `except
  Exception` instances in the codebase are intentional boundary
  handlers (JSON-RPC dispatcher, async watchdog loops, security log
  fallbacks) where narrowing would harm correctness.

## [1.2.50] - 2026-05-09

### Changed
- Audit (A1 continued): narrowed broad `except Exception` clauses on
  the application boot / request middleware path so unexpected errors
  no longer hide as "JWKS empty" / "JWT verification failed" with no
  signal of what actually went wrong.
- `app.py` (2 sites narrowed, 1 left intentionally broad):
  - `_apply_dynamic_settings` boot wrapper narrowed to
    `(AttributeError, TypeError, ValueError, KeyError)` — these are the
    only ways a settings JSON can fail to mount onto the dataclass.
  - `/jwks.json` RS256 build narrowed to `(ValueError, TypeError,
    cryptography.exceptions.UnsupportedAlgorithm)` — covers malformed
    PEM, non-bytes encode and unsupported key algorithms; nothing else
    in the block can raise.
  - `rate_limit_cleanup()` async watchdog loop kept as broad
    `Exception` on purpose. Its job is to keep the loop alive on any
    cleanup failure; narrowing risks killing the long-lived task on
    an unforeseen error type.
- `middleware.py:313` JWT verification narrowed to
  `(jwt.PyJWTError, sqlite3.Error, ValueError, KeyError)` — covers
  every failure verifying / blacklist-checking a token.
- `admin_auth.py:107` admin-route auth narrowed to
  `(jwt.PyJWTError, sqlite3.Error, ValueError, KeyError, TypeError)`
  — `TypeError` covers `int(payload.get("sub"))` when `sub` is `None`.

### Notes
- No behaviour change on the happy path. 184 tests pass.
- 8 of the originally-flagged 14 audit-worthy catches have now been
  narrowed across 1.2.49 + 1.2.50; the remaining 6 in `cli.py` and
  `setup_wizard.py` are next.

## [1.2.49] - 2026-05-09

### Changed
- Audit (A1 continued): narrowed 7 broad `except Exception` clauses on
  the configuration / persistence path so unexpected error types are no
  longer silently swallowed.
- `config.py` (3 sites):
  - `JWTConfig.__post_init__` auto-create of `.env` — now `OSError`
    only.
  - `_load_jwt_keys` private/public RSA key file reads — now `OSError`
    only (`FileNotFoundError` was already handled separately above).
- `settings_manager.py` (4 sites):
  - `_load_settings` JSON file read narrowed to `(OSError,
    json.JSONDecodeError, ValueError)`. A corrupt or schema-broken
    `auth_settings.json` still falls back to defaults, but unknown
    runtime errors are no longer masked.
  - `_load_settings` initial-save, `_backfill_defaults` save, and
    public `save()` write paths narrowed to `OSError` only.
- `db.py` `get_db` context manager left as `except Exception`
  intentionally — that catch is a generic safety-net that must rollback
  the transaction for any error raised inside the `with` block (not
  just `sqlite3.Error`), so narrowing would break correctness.

### Notes
- No behaviour change on the happy path. 184 tests pass.
- Continues the broad-except narrowing campaign started in 1.2.35.

## [1.2.48] - 2026-05-09

### Changed
- Refactor: extracted four named exception-class tuples to a new
  module `mcp/_exceptions.py` so the recurring backend-failure catch
  sets are no longer duplicated across `mcp/proxy.py`, `mcp/health.py`,
  and `mcp/handler.py`:
  - `PROXY_TRANSPORT_ERRORS` — `(httpx.HTTPError, json.JSONDecodeError,
    ValueError, KeyError)` — used at 6 per-server fetch / broadcast
    sites in `mcp/proxy.py`.
  - `PROXY_DISCOVERY_ERRORS` — adds `RuntimeError` for backends that
    turn JSON-RPC errors into Python exceptions during initialize.
    2 sites (`proxy._fetch_capabilities_from_server`, health-check
    `_initialize_session`).
  - `PROXY_DISCOVERY_DB_ERRORS` — adds `sqlite3.Error` for paths that
    also cache to SQLite. 2 sites (handler `_handle_initialize`,
    health-check per-server fallback).
  - `PROXY_TOKEN_REFRESH_ERRORS` — `(httpx.HTTPError, sqlite3.Error,
    ValueError, KeyError)` for the OAuth2 refresh-retry block.
    2 sites (`proxy._proxy_jsonrpc`, health-check 401 retry).
- Total: 12 long literal tuples replaced with a single named constant
  per call site. Adding/removing a backend error class now needs one
  edit instead of 12.
- Cleanup: removed now-unused `import httpx` / `import json` /
  `import sqlite3` from `mcp/handler.py` and `mcp/health.py` (they
  were only referenced inside the literal except tuples).

### Notes
- No behaviour change. 184 tests pass. Final of three planned
  helper-extraction releases.

## [1.2.47] - 2026-05-09

### Changed
- Refactor: extracted `try_upgrade_password_hash()` helper in
  `auth/user_store.py`. Five identical try/except blocks across
  `auth/endpoints.py` (login + /oauth/token password grant),
  `auth/authorize_endpoint.py`, `admin/login.py`, and
  `admin/user_pages.py` are now a single call:
  ```python
  try_upgrade_password_hash(db_path, user["id"], upgraded_hash, username)
  ```
  Each call site shrinks from 5 lines to 1.
- Added module-level `logger` to `auth/user_store.py` (separate from
  the file-based audit logger) so the helper can surface DB-write
  failures via the standard logging stack.

### Security (incidental)
- `admin/login.py` admin-portal password-hash upgrade now narrows
  `except Exception:` to `sqlite3.Error` — the last broad catch I
  missed during the A1 pass on this file.

### Notes
- No behaviour change for documented paths. 184 tests pass. Second
  of three planned helper-extraction releases.

## [1.2.46] - 2026-05-09

### Changed
- Refactor: extracted `_verify_user_token_or_401()` helper in
  `admin/user_pages.py`. Three byte-identical try/except blocks
  (the JWT-verify + JTI-blacklist + admin-rejection sequence used
  by `/account/api/get-token`, `/account/api/regenerate`, and
  `/account/api/info`) collapsed into a single helper. Each call site
  now reads:
  ```
  payload, error = _verify_user_token_or_401(token, _config)
  if error:
      return error
  ```
- Hoisted `verify_token`, `decode_token_unsafe`, and
  `is_token_blacklisted` imports to module level (they're now used
  by the shared helper).

### Notes
- No behaviour change. 184 tests pass. This is the first of three
  planned helper-extraction releases motivated by patterns surfaced
  during the A1 narrowing pass.

## [1.2.45] - 2026-05-09

### Changed
- Closed `admin/user_pages.py` for the audit's A1 finding by narrowing
  all seven `except Exception` blocks. No broad catch remains in this
  file:
  - Page-level `verify_token` for `/account` (redirects to /login on
    failure): `jwt.PyJWTError`.
  - User lookup for friendly username (`get_user_by_id` + int conversion
    on `payload["sub"]`): `(sqlite3.Error, ValueError, TypeError)`.
  - Password-hash upgrade after login: `sqlite3.Error`.
  - Three token-verify-and-blacklist combos (`/account/api/profile`,
    `/account/api/get-token`, `/account/api/regenerate`):
    `(jwt.PyJWTError, sqlite3.Error)`.
  - `expires_in_seconds` datetime arithmetic on token-info responses:
    `(TypeError, ValueError, AttributeError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.44] - 2026-05-09

### Changed
- Closed `mcp/token_manager.py` for the audit's A1 finding by narrowing
  all three `except Exception` blocks. No broad catch remains:
  - Encrypt + persist refresh token: `(sqlite3.Error, ValueError)`.
    `encrypt_token` raises `ValueError` on missing/malformed key; the
    DB write surfaces `sqlite3.Error`. Both are non-fatal — the
    in-memory cache keeps refresh working until process restart.
  - Decrypt + cache load on startup: `(sqlite3.Error, ValueError)`.
  - OAuth2 refresh-flow outer wrap: `(httpx.HTTPError,
    json.JSONDecodeError, ValueError, KeyError, sqlite3.Error)` —
    HTTP POST + JSON parse + audit/store DB writes.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.43] - 2026-05-09

### Security
- Closed the silent suppression in `mcp/health.py`: the
  `notifications/initialized` best-effort send during health-check
  initialize previously swallowed all exceptions with `pass`. It now
  catches only `httpx.HTTPError` and logs at DEBUG with the affected
  server name, mirroring the equivalent fix in `mcp/proxy.py` (1.2.38).

### Changed
- Closed `mcp/health.py` for the audit's A1 finding by narrowing the
  remaining `except Exception` blocks:
  - Health-check loop guard (top of `_health_check_loop`): kept broad
    with `# noqa: BLE001` and a comment — this is an intentional
    long-running-loop backstop that must absorb anything to keep the
    checker alive between intervals.
  - Token-refresh attempt during 401 handling: `(httpx.HTTPError,
    sqlite3.Error, ValueError, KeyError)`.
  - Per-server check fallback (after specific TimeoutException /
    HTTPStatusError): `(httpx.HTTPError, json.JSONDecodeError,
    ValueError, KeyError, sqlite3.Error, RuntimeError)`.
  - Initialize attempt outer: `(httpx.HTTPError, json.JSONDecodeError,
    ValueError, KeyError, RuntimeError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.42] - 2026-05-09

### Changed
- Closed `security/logger.py` for the audit's A1 finding by narrowing
  all seven `except Exception` blocks. No broad catch remains in this
  file:
  - `log_security_event` write: `sqlite3.Error`.
  - `log_mcp_request` write: `sqlite3.Error`.
  - MCP DB size-check + auto-cleanup (PRAGMA + cleanup_old_logs):
    `(sqlite3.Error, OSError)` — cleanup also writes a JSONL archive.
  - `cleanup_old_logs`: `(sqlite3.Error, OSError)`.
  - `get_security_events`: `sqlite3.Error`.
  - `get_mcp_request_stats`: `sqlite3.Error`.
  - `get_mcp_requests` (DB → file fallback): `(sqlite3.Error, OSError,
    KeyError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.41] - 2026-05-09

### Changed
- Closed `auth/authorize_endpoint.py` for the audit's A1 finding by
  narrowing all six `except Exception` blocks. No broad catch remains
  in this file:
  - redirect_uri parser → `ValueError` (matches the explicit raise).
  - DCR client lookup outer wrap → `sqlite3.Error` (CIMD failures are
    already caught with a focused 400 inside the URL-client branch).
  - `update_oauth_client_last_seen` post-login → `sqlite3.Error`.
  - Rate-limit-check defensive guard → `(AttributeError, KeyError)`
    so genuine runtime errors propagate but a malformed
    `AppConfig.rate_limit` shape doesn't block /authorize.
  - Password-hash upgrade on /authorize POST → `sqlite3.Error`.
  - Authorization-code generation + audit log outer → `(sqlite3.Error,
    OSError)`.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.40] - 2026-05-09

### Changed
- Closed `auth/endpoints.py` for the audit's A1 finding by narrowing
  the remaining 12 `except Exception` blocks (best-effort logs and
  JWT verify residue paths). All catches in this file now declare
  the specific exception types they handle:
  - Password-hash upgrade in /auth/login and /oauth/token: `sqlite3.Error`.
  - `update_last_login` post-login: `sqlite3.Error`.
  - JWT verify residue catches in /auth/refresh, /auth/logout and
    /auth/me (which sit after `jwt.ExpiredSignatureError` and
    `jwt.InvalidTokenError`): `jwt.PyJWTError` — covers any sibling
    PyJWT subclass while letting non-JWT runtime errors propagate.
  - `revoke_refresh_token` on logout: `sqlite3.Error`.
  - `log_auth_event` (logout audit write): `(sqlite3.Error, OSError)`
    — SQLite write plus rotating file logger.
  - Blacklist short-circuit in /auth/me (decode + DB):
    `(jwt.PyJWTError, sqlite3.Error)`.
  - Three `update_oauth_client_*` post-issue meta updates:
    `sqlite3.Error`.
- The single broad `except Exception` left in the file is the outer
  /oauth/token last-resort wrap, already annotated with
  `# noqa: BLE001` since 1.2.37.

### Notes
- No behaviour change. 184 tests pass. This release is pure narrowing
  of already-logged catches; combined with 1.2.36 (Cat A) and 1.2.37
  (Cat B), `auth/endpoints.py` is now fully audited for the A1
  finding (27 sites total, 26 narrowed + 1 intentional outer wrap).

## [1.2.39] - 2026-05-09

### Changed
- Annotated the nine intentional broad `except Exception` blocks in
  `mcp/handler.py` with `# noqa: BLE001` and explanatory comments.
  These are the JSON-RPC dispatcher backstops (one outer, eight
  per-method) that translate any escaped exception into a JSON-RPC
  `-32603` internal-error response so the MCP client never sees a
  Python traceback. They were already logging via `logger.exception`;
  this release just documents the intent for future reviewers.
- Narrowed the two non-backstop catches:
  - `_handle_initialize` capabilities discovery now catches only
    `(httpx.HTTPError, json.JSONDecodeError, ValueError, KeyError,
    RuntimeError, sqlite3.Error)` — the same exception domain as
    `proxy._fetch_capabilities_from_server`.
  - `_log_mcp` security-log helper now catches only
    `(sqlite3.Error, OSError)` so unrelated runtime errors propagate.

### Notes
- No behaviour change. 184 tests pass.

## [1.2.38] - 2026-05-09

### Security
- Closed four silent-suppression sites in `mcp/proxy.py` that were
  swallowing exceptions with `pass`, `continue`, or `return []` and
  no log line:
  - `notifications/initialized` best-effort send (post-init handshake).
  - Broadcast lookup of a `resource_uri` across backend servers.
  - Per-server `resources/templates/list` fetch.
  - Broadcast lookup of a `prompt_name` across backend servers.

  Each now logs the failure at DEBUG with the affected server and
  identifier, so operators can correlate degraded backend behaviour
  with broadcast iteration.

### Changed
- Narrowed the seven other broad `except Exception` blocks in
  `mcp/proxy.py` to the types that can actually surface from
  `httpx.AsyncClient` calls plus our own JSON parsing:
  `(httpx.HTTPError, json.JSONDecodeError, ValueError, KeyError)`,
  with `sqlite3.Error` added where the block also writes to SQLite
  (token-refresh path, tools-fetch fallback). Truly unexpected errors
  now propagate instead of being relabelled.
- The single intentional broad catch left in place is the one in
  `call_tool` that mirrors any exception onto the dedup-inflight
  Future before re-raising. It now carries `# noqa: BLE001` and a
  comment explaining why a wide catch is required there.
- The capabilities-fetch fallback also accepts `RuntimeError` so
  backends that turn a JSON-RPC "already initialized" response into
  a Python exception continue to be handled gracefully (caught by
  `tests/test_mcp_proxy.py::test_fetch_capabilities_handles_already_initialized_as_non_fatal`).

### Notes
- No behaviour change for any documented happy/error path; the
  184-test suite still passes.

## [1.2.37] - 2026-05-09

### Security
- Narrowed 10 last-resort `except Exception` blocks in
  `auth/endpoints.py` (audit Category B):
  - The four request-body parsers (`/auth/register`, `/auth/login`,
    `/auth/refresh`, `/auth/logout`) now catch only
    `(json.JSONDecodeError, TypeError)` for the post-Pydantic fallback,
    so genuinely unexpected exceptions surface instead of being
    relabelled as "Invalid request body".
  - User creation (`create_user` block) catches only
    `(sqlite3.Error, OSError)`.
  - Login/refresh token issuance and persistence catch only
    `(jwt.PyJWTError, sqlite3.Error)` (login refresh-token save also
    catches `ValueError` for the explicit `raise` on a missing `exp`).
  - Logout blacklist catches only `(sqlite3.Error, ValueError, OSError)`.
- The single broad catch left in place is the outer last-resort wrap
  around `/oauth/token`'s ~570-line grant dispatch. It is now annotated
  with a comment and an explicit `# noqa: BLE001` so reviewers see it
  is intentional.

### Notes
- No behaviour change for any documented happy or error path; the
  existing integration tests for login / refresh / logout / register /
  oauth_token continue to pass unchanged.

## [1.2.36] - 2026-05-09

### Security
- Narrowed silent-fallback helpers in `auth/endpoints.py`. The three
  affected helpers were swallowing every exception class and returning
  defaults with no log line, which masked configuration / parser bugs:
  - `_get_token_ttl` and `_get_password_policy` now catch only
    `RuntimeError` from `get_settings_manager()` and log at DEBUG. Any
    other failure surfaces normally.
  - `_parse_basic_auth` now catches only
    `(binascii.Error, UnicodeDecodeError, ValueError)` and logs at
    DEBUG. Headers without a `:` separator are detected explicitly
    instead of by exception, fixing the previous reliance on
    `str.split(":", 1)` raising on missing separator (which it does
    not — the prior fallback path was effectively dead code).

### Added
- `tests/test_endpoints_helpers.py` with 11 characterization tests
  covering happy/fallback paths for the three helpers, including
  `Basic` auth parsing edge cases (missing/non-Basic scheme,
  malformed base64, invalid UTF-8, no colon, password with embedded
  colons).

## [1.2.35] - 2026-05-09

### Security
- Narrowed broad `except Exception: pass` blocks in `auth/token_service.py`:
  - `verify_token` failures during reuse are now caught only as
    `jwt.PyJWTError` and logged at DEBUG.
  - `is_token_blacklisted` errors are caught only as `sqlite3.Error` and
    logged at WARNING; the caller still rotates safely.
  - Failures of `blacklist_token` (single-session enforcement and
    explicit rotation) are caught only as `sqlite3.Error` and logged at
    ERROR with `exc_info`. Previously they were silently swallowed,
    which meant a transient DB error could leave the previous session
    valid until natural expiry without any operator visibility.
- `_parse_expires_at` now catches `(ValueError, TypeError)` instead of
  bare `Exception`, so unexpected runtime errors no longer surface as
  silent `None`.

### Added
- `tests/test_token_service.py`: 22 characterization tests covering token
  reuse, JTI-mismatch rotation, garbage-input handling, single-session
  enforcement, admin/user store separation, and rotation blacklisting.
  The module previously had 0% coverage.

## [1.2.34] - 2026-05-09

### Security
- **CIMD (Client ID Metadata Documents)**: When `/authorize` receives a
  URL-formatted `client_id`, the gateway now fetches the metadata document
  per the MCP authorization spec and `draft-ietf-oauth-client-id-metadata-document-00`,
  then exact-matches the request's `redirect_uri` against
  `metadata.redirect_uris`. Replaces the previous same-origin fallback,
  closing the path-on-legitimate-host redirect risk.
- SSRF protection on metadata fetch: HTTPS only, non-empty path component,
  refusal of private/loopback/link-local/reserved targets (incl. AWS
  instance-metadata `169.254.169.254` and IPv6 `::1`), 1 MB body cap, 5s
  timeout, no redirects.

### Added
- `auth/cimd.py` module with metadata fetch, validation, and an in-memory
  cache that honours `Cache-Control` `max-age` / `no-store`.
- 22 unit tests for CIMD plus 4 integration tests on `/authorize`.

## [1.2.33] - 2026-05-09

### Security
- **OAuth scope allowlist** (OAuth 2.1 §3.3 / RFC 6749 §3.3): `/authorize`
  and `/oauth/register` now reject any scope outside
  `AuthConfig.allowed_scopes` (default: `openid`, `profile`, `email`,
  `offline_access`). Configurable via `AUTH_ALLOWED_SCOPES`.

### Changed
- `.well-known/oauth-authorization-server` and
  `.well-known/openid-configuration` derive `scopes_supported` from the
  configured allowlist; `code_challenge_methods_supported` is now `["S256"]`
  only (matches the enforcement added in 1.2.32).
- `.well-known/oauth-protected-resource` no longer advertises
  `offline_access` in `scopes_supported` — the MCP authorization spec says
  resource metadata SHOULD NOT include it.

### Added
- `utils.validate_scopes()` helper.

## [1.2.32] - 2026-05-09

### Security
- **PKCE enforcement** (OAuth 2.1 §4.1.1 / RFC 7636 / MCP authorization
  spec): `/authorize` rejects requests without `code_challenge`; only
  `S256` is accepted as `code_challenge_method`. The token endpoint
  refuses to exchange any code that lacks a bound challenge or whose
  method is not `S256` (defense in depth). PKCE comparison switched to
  `hmac.compare_digest`.

### Repository
- Removed `tests/` from `.gitignore`. The full test suite (115 tests
  prior to this release) now ships in the repository instead of living
  only on the maintainer's machine.

## [1.2.31] - 2026-05-09

### Security
- Replaced raw `==` comparisons with `hmac.compare_digest` for the DCR
  initial access token (`auth/dcr_endpoints.py`) and the OAuth client
  secret hash (`auth/client_store.py`), closing two timing-side-channel
  paths.
- The auto-generated `JWT_SECRET_KEY` is no longer printed to `stderr`
  on first run; the operator is pointed to a generation command instead.

### Changed
- Added `.flake8` configuration that defers line length to `black` and
  excludes inline-HTML files. `make lint` now passes with zero warnings.
- Hoisted late imports out of `admin/routes.py` to fix `E402`.

## [1.2.30] - 2026-05-09

### Added
- `Makefile` consolidating dev, build, release, and Docker workflows
  (`make help` for a list). Replaces the ad-hoc `scripts/publish.sh`,
  which has been removed.
- `make docker-release` rebuilds the container with the current
  `GIT_COMMIT` injected so the admin footer reports the right commit.

### Fixed
- Replaced deprecated `datetime.datetime.utcnow()` with timezone-aware
  `datetime.now(timezone.utc)` in `logging_config.py`,
  `admin/logs_api.py`, and `security/mcp_auditor.py`. The previous
  combination of naive `utcnow()` and `+ "Z"` produced ISO timestamps
  that were technically correct but, when compared with timezone-aware
  values, would have raised `TypeError`.

## [1.2.29] - 2026-04-16

### Fixed
- Applied configured backend `tool_prefix` values to tool names returned from the
  aggregated `/mcp` endpoint while preserving raw backend names on per-server
  endpoints.
- Mapped prefixed aggregate tool names back to raw backend tool names for
  `tools/call`, keeping prefixed listings and execution routing consistent.

## [1.2.28] - 2026-04-16

### Changed
- Marked the package as `Production/Stable` in PyPI metadata instead of `Beta`.
- Expanded PyPI classifiers to better reflect the runtime and deployment model:
  `Environment :: Web Environment`, `Framework :: AsyncIO`,
  `Topic :: Internet :: Proxy Servers`, `Topic :: Security :: Cryptography`,
  `Topic :: System :: Monitoring`, and
  `Topic :: System :: Systems Administration :: Authentication/Directory`.

## [1.2.27] - 2026-03-21

### Fixed
- Omitted `null` fields such as `client_secret` and `scope` from Dynamic Client
  Registration responses when those values are not issued, improving strict client
  compatibility.
- Added `id_token` to the authorization code token response when `openid` is
  requested.
- Returned `scope` in the authorization code token response for better OAuth/OIDC
  interoperability.
- Improved `/auth/me` compatibility for OIDC-style userinfo consumers.

### Changed
- Improved ChatGPT connector compatibility for OAuth, DCR, and authorization code
  flows.

[1.2.54]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.54
[1.2.53]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.53
[1.2.52]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.52
[1.2.51]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.51
[1.2.50]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.50
[1.2.49]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.49
[1.2.48]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.48
[1.2.47]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.47
[1.2.46]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.46
[1.2.45]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.45
[1.2.44]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.44
[1.2.43]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.43
[1.2.42]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.42
[1.2.41]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.41
[1.2.40]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.40
[1.2.39]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.39
[1.2.38]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.38
[1.2.37]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.37
[1.2.36]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.36
[1.2.35]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.35
[1.2.34]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.34
[1.2.33]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.33
[1.2.32]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.32
[1.2.31]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.31
[1.2.30]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.30
[1.2.29]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.29
[1.2.28]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.28
[1.2.27]: https://github.com/loglux/authmcp-gateway/releases/tag/v1.2.27
