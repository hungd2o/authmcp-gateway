#!/usr/bin/env python3
"""Fail if coverage for critical modules drops below configured thresholds."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--coverage-json", required=True, help="Path to coverage json report")
    parser.add_argument("--thresholds", required=True, help="Path to thresholds json")
    return parser.parse_args()


def _file_coverage(files: dict, key: str) -> float:
    if key not in files:
        raise KeyError(f"Missing coverage entry for {key}")
    summary = files[key].get("summary", {})
    for field in ("percent_covered", "percent_covered_display"):
        if field in summary:
            return float(summary[field])
    raise KeyError(f"No percent_covered field for {key}")


def main() -> int:
    args = parse_args()

    coverage_payload = json.loads(Path(args.coverage_json).read_text(encoding="utf-8"))
    thresholds_payload = json.loads(Path(args.thresholds).read_text(encoding="utf-8"))

    files = coverage_payload.get("files", {})
    modules = thresholds_payload.get("modules", {})

    if not modules:
        print("No modules configured in thresholds file")
        return 2

    failures: list[str] = []

    for module_path, min_percent in modules.items():
        try:
            actual = _file_coverage(files, module_path)
        except KeyError as exc:
            failures.append(str(exc))
            continue

        if actual < float(min_percent):
            failures.append(f"{module_path}: {actual:.2f}% < required {float(min_percent):.2f}%")
        else:
            print(f"OK  {module_path}: {actual:.2f}% >= {float(min_percent):.2f}%")

    if failures:
        print("\nCoverage gate failed:")
        for failure in failures:
            print(f" - {failure}")
        return 1

    print("\nCoverage gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
