"""Tests for OAuth Client ID Metadata Document (CIMD) handling.

Per MCP authorization spec / draft-ietf-oauth-client-id-metadata-document-00.
"""

import httpx
import pytest

from authmcp_gateway.auth.cimd import (
    CIMDError,
    clear_cache,
    fetch_client_metadata,
    is_redirect_uri_in_metadata,
)


@pytest.fixture(autouse=True)
def _reset_cache():
    """Clear the CIMD cache between tests."""
    clear_cache()
    yield
    clear_cache()


def _mock_client(handler) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(handler))


def _allow_any_target(_host: str) -> bool:
    """Bypass DNS-based SSRF check for fetch-logic tests."""
    return True


def _valid_metadata_for(url: str) -> dict:
    return {
        "client_id": url,
        "client_name": "Example Client",
        "redirect_uris": [
            "https://example.com/oauth/callback",
            "https://example.com/oauth/callback2",
        ],
    }


# ---------- URL validation (no fetch) ----------


def test_cimd_rejects_http_scheme():
    with pytest.raises(CIMDError, match="https"):
        fetch_client_metadata("http://example.com/client.json")


def test_cimd_rejects_missing_path_component():
    """Per spec: client_id URL MUST contain a path component."""
    with pytest.raises(CIMDError, match="path"):
        fetch_client_metadata("https://example.com")


def test_cimd_rejects_root_path():
    """A bare '/' isn't a real path component."""
    with pytest.raises(CIMDError, match="path"):
        fetch_client_metadata("https://example.com/")


def test_cimd_rejects_userinfo_in_url():
    with pytest.raises(CIMDError, match="user"):
        fetch_client_metadata("https://user:pass@example.com/client.json")


def test_cimd_rejects_fragment_in_url():
    with pytest.raises(CIMDError, match="fragment"):
        fetch_client_metadata("https://example.com/client.json#frag")


# ---------- SSRF protection (uses literal IPs to avoid DNS in tests) ----------


def test_cimd_rejects_loopback_ipv4():
    with pytest.raises(CIMDError, match="non-public|host"):
        fetch_client_metadata("https://127.0.0.1/client.json")


def test_cimd_rejects_private_ipv4_10():
    with pytest.raises(CIMDError, match="non-public|host"):
        fetch_client_metadata("https://10.0.0.1/client.json")


def test_cimd_rejects_private_ipv4_192_168():
    with pytest.raises(CIMDError, match="non-public|host"):
        fetch_client_metadata("https://192.168.1.1/client.json")


def test_cimd_rejects_link_local_aws_metadata():
    """169.254.169.254 is the AWS instance metadata endpoint — classic SSRF target."""
    with pytest.raises(CIMDError, match="non-public|host"):
        fetch_client_metadata("https://169.254.169.254/client.json")


def test_cimd_rejects_loopback_ipv6():
    with pytest.raises(CIMDError, match="non-public|host"):
        fetch_client_metadata("https://[::1]/client.json")


# ---------- Fetch + metadata validation (mocked httpx) ----------


def test_cimd_fetches_valid_metadata():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        return httpx.Response(200, json=_valid_metadata_for(url))

    with _mock_client(handler) as client:
        metadata = fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)
    assert metadata["client_id"] == url
    assert "redirect_uris" in metadata


def test_cimd_rejects_metadata_client_id_mismatch():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        bad = _valid_metadata_for(url)
        bad["client_id"] = "https://attacker.example.com/client.json"
        return httpx.Response(200, json=bad)

    with _mock_client(handler) as client:
        with pytest.raises(CIMDError, match="client_id"):
            fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)


def test_cimd_rejects_missing_redirect_uris_field():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        m = _valid_metadata_for(url)
        del m["redirect_uris"]
        return httpx.Response(200, json=m)

    with _mock_client(handler) as client:
        with pytest.raises(CIMDError, match="redirect_uris|required"):
            fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)


def test_cimd_rejects_missing_client_name_field():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        m = _valid_metadata_for(url)
        del m["client_name"]
        return httpx.Response(200, json=m)

    with _mock_client(handler) as client:
        with pytest.raises(CIMDError, match="client_name|required"):
            fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)


def test_cimd_rejects_non_json_body():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        return httpx.Response(200, content=b"<html>not json</html>")

    with _mock_client(handler) as client:
        with pytest.raises(CIMDError, match="JSON"):
            fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)


def test_cimd_rejects_empty_redirect_uris_list():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        m = _valid_metadata_for(url)
        m["redirect_uris"] = []
        return httpx.Response(200, json=m)

    with _mock_client(handler) as client:
        with pytest.raises(CIMDError, match="redirect_uris"):
            fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)


def test_cimd_rejects_http_error_status():
    url = "https://example.com/oauth/client.json"

    def handler(_request):
        return httpx.Response(404, json={"error": "not found"})

    with _mock_client(handler) as client:
        with pytest.raises(CIMDError, match="404|HTTP"):
            fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)


# ---------- Redirect URI matching ----------


def test_is_redirect_uri_in_metadata_exact_match():
    metadata = {"redirect_uris": ["https://example.com/cb1", "https://example.com/cb2"]}
    assert is_redirect_uri_in_metadata(metadata, "https://example.com/cb1") is True
    assert is_redirect_uri_in_metadata(metadata, "https://example.com/cb2") is True


def test_is_redirect_uri_in_metadata_rejects_unregistered():
    metadata = {"redirect_uris": ["https://example.com/cb1"]}
    assert is_redirect_uri_in_metadata(metadata, "https://example.com/cb3") is False


def test_is_redirect_uri_in_metadata_no_partial_match():
    """Partial / prefix matches must not be accepted (exact-match per OAuth 2.1)."""
    metadata = {"redirect_uris": ["https://example.com/cb"]}
    assert is_redirect_uri_in_metadata(metadata, "https://example.com/cb/extra") is False
    assert is_redirect_uri_in_metadata(metadata, "https://example.com/cb?x=1") is False


# ---------- Cache behaviour ----------


def test_cimd_caches_successful_response():
    """Second call for the same URL should not hit the transport."""
    url = "https://example.com/oauth/client.json"
    call_count = {"n": 0}

    def handler(_request):
        call_count["n"] += 1
        return httpx.Response(
            200,
            json=_valid_metadata_for(url),
            headers={"Cache-Control": "max-age=600"},
        )

    with _mock_client(handler) as client:
        fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)
        fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)
    assert call_count["n"] == 1


def test_cimd_does_not_cache_when_no_store():
    url = "https://example.com/oauth/client.json"
    call_count = {"n": 0}

    def handler(_request):
        call_count["n"] += 1
        return httpx.Response(
            200,
            json=_valid_metadata_for(url),
            headers={"Cache-Control": "no-store"},
        )

    with _mock_client(handler) as client:
        fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)
        fetch_client_metadata(url, http_client=client, _check_target=_allow_any_target)
    assert call_count["n"] == 2
