"""Recurring exception-class tuples for MCP backend error handling.

Centralises the catch-set tuples used across ``mcp/proxy.py``,
``mcp/health.py``, and ``mcp/handler.py`` so that changing the expected
backend-failure surface (e.g. adding a new ``httpx`` subclass or removing
an obsolete one) only requires editing one place.

These constants are intentionally module-level tuples rather than helpers
so they can be passed directly to ``except`` clauses:

    from authmcp_gateway.mcp._exceptions import PROXY_TRANSPORT_ERRORS
    try:
        ...
    except PROXY_TRANSPORT_ERRORS as exc:
        ...
"""

import json
import sqlite3

import httpx

#: Errors raised by ``httpx`` plus our JSON-RPC response parsing.
#: Used for per-server tool/resource/prompt fetches and broadcast loops
#: in ``mcp/proxy.py``. ``KeyError`` covers dict access on malformed
#: backend responses.
PROXY_TRANSPORT_ERRORS = (
    httpx.HTTPError,
    json.JSONDecodeError,
    ValueError,
    KeyError,
)

#: Capabilities-discovery errors. Extends :data:`PROXY_TRANSPORT_ERRORS`
#: with ``RuntimeError`` because some backends translate JSON-RPC error
#: responses ("already initialized") into a Python exception.
PROXY_DISCOVERY_ERRORS = PROXY_TRANSPORT_ERRORS + (RuntimeError,)

#: Discovery + capabilities caching. Extends :data:`PROXY_DISCOVERY_ERRORS`
#: with ``sqlite3.Error`` for the cache write inside the handler / health
#: check.
PROXY_DISCOVERY_DB_ERRORS = PROXY_DISCOVERY_ERRORS + (sqlite3.Error,)

#: OAuth2 refresh-token retry path. The flow does an HTTP POST and a DB
#: write of the new token; ``ValueError`` / ``KeyError`` cover malformed
#: response payloads.
PROXY_TOKEN_REFRESH_ERRORS = (
    httpx.HTTPError,
    sqlite3.Error,
    ValueError,
    KeyError,
)
