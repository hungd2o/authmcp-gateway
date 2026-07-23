import pytest

from authmcp_gateway.mcp.outbound_network_policy import (
    OutboundDestinationError,
    validate_virtual_http_destination,
)


def test_virtual_http_policy_allows_reviewed_public_destination():
    validate_virtual_http_destination(
        "https://8.8.8.8/users/{{arguments.id}}",
        "https://8.8.8.8/users/123",
    )


@pytest.mark.parametrize("url", ["http://127.0.0.1", "http://169.254.169.254", "http://10.0.0.1"])
def test_virtual_http_policy_blocks_private_destinations(url):
    with pytest.raises(OutboundDestinationError, match="blocked network"):
        validate_virtual_http_destination(url, url)


def test_virtual_http_policy_rejects_dynamic_authority():
    with pytest.raises(OutboundDestinationError, match="scheme, host, or port"):
        validate_virtual_http_destination("https://api.example.test/{{arguments.url}}", "https://evil.test/")
