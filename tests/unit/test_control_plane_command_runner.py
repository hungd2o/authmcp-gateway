from __future__ import annotations

import sys

import pytest

from authmcp_gateway.mcp.control_plane_command_runner import MAX_OUTPUT_BYTES, run_command
from authmcp_gateway.mcp.control_plane_native_client import ManagementUnavailableError


def test_command_runner_rejects_output_before_it_can_grow_unbounded():
    with pytest.raises(ManagementUnavailableError, match="output is too large"):
        run_command(
            sys.executable,
            ["-c", f"import sys; sys.stdout.write('x' * {MAX_OUTPUT_BYTES + 1})"],
        )
