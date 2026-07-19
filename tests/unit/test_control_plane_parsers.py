from __future__ import annotations

import pytest

from authmcp_gateway.mcp.control_plane_manifests import load_manifest
from authmcp_gateway.mcp.control_plane_parsers import OutputParseError, parse_output


GITNEXUS_LIST = """  Indexed Repositories (1)

  SensorPredictor
    Path:    E:\\WorkSpace\\SensorPredictor
    Indexed: 5/24/2026, 6:19:28 PM
    Commit:  37aa8e7
    Stats:   169 files, 12440 symbols, 16038 edges
    Clusters:   254
    Processes:  300
"""


def test_delimited_parser_requires_its_reviewed_header():
    config = {"kind": "delimited-v1", "delimiter": "\t", "columns": ["repo_id", "root"]}

    assert parse_output("repo_id\troot\nrepo-a\tE:\\repo-a\n", config) == [
        {"repo_id": "repo-a", "root": "E:\\repo-a"}
    ]
    with pytest.raises(OutputParseError, match="header"):
        parse_output("alias\troot\nrepo-a\tE:\\repo-a\n", config)


def test_gitnexus_profile_parses_its_reviewed_cli_output():
    config = load_manifest("gitnexus")["commands"]["entities_list"]["parser"]

    assert parse_output(GITNEXUS_LIST, config) == [{
        "name": "SensorPredictor", "path": "E:\\WorkSpace\\SensorPredictor",
        "indexed": "5/24/2026, 6:19:28 PM", "commit": "37aa8e7",
        "files": "169", "symbols": "12440", "edges": "16038",
        "clusters": "254", "processes": "300",
    }]
    with pytest.raises(OutputParseError, match="approved parser"):
        parse_output("GitNexus changed its list output", config)
