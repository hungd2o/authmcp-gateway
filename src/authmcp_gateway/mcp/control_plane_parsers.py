"""Bounded, declarative parsers for reviewed command output."""

from __future__ import annotations

import csv
import io
import re
from typing import Any

import textfsm


class OutputParseError(ValueError):
    """A command result did not match its reviewed parser profile."""


def parse_output(output: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    kind = config.get("kind")
    if kind == "delimited-v1":
        return _parse_delimited(output, config)
    if kind == "textfsm-v1":
        return _parse_textfsm(output, config)
    raise OutputParseError("command parser is unsupported")


def _parse_delimited(output: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    delimiter = config.get("delimiter")
    columns = config.get("columns")
    if delimiter not in {"\t", ","} or not isinstance(columns, list) or not columns:
        raise OutputParseError("delimited parser configuration is invalid")
    rows = list(csv.reader(io.StringIO(output), delimiter=delimiter))
    if not rows or rows[0] != columns:
        raise OutputParseError("command header does not match the approved parser")
    if any(len(row) != len(columns) for row in rows[1:]):
        raise OutputParseError("command row does not match the approved parser")
    return [dict(zip(columns, row, strict=True)) for row in rows[1:] if any(row)]


def _parse_textfsm(output: str, config: dict[str, Any]) -> list[dict[str, Any]]:
    template = config.get("template")
    fields = config.get("fields")
    required_pattern = config.get("required_pattern")
    if not isinstance(template, str) or not isinstance(fields, dict) or not isinstance(required_pattern, str):
        raise OutputParseError("TextFSM parser configuration is invalid")
    if not re.search(required_pattern, output, flags=re.MULTILINE):
        raise OutputParseError("command output does not match the approved parser")
    try:
        parser = textfsm.TextFSM(io.StringIO(template))
        rows = parser.ParseText(output)
    except textfsm.Error as exc:
        raise OutputParseError("command output does not match the approved parser") from exc
    headers = [header.lower() for header in parser.header]
    if set(fields) - set(headers):
        raise OutputParseError("TextFSM fields do not match its parser template")
    return [{fields.get(key, key): value for key, value in zip(headers, row, strict=True)} for row in rows]
