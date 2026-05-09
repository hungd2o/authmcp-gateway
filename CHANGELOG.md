# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
