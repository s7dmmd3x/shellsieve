"""Export scan results to various machine-readable formats (JSON, CSV, SARIF)."""

from __future__ import annotations

import csv
import io
import json
from typing import Literal

from shellsieve.scanner import ScanResult

ExportFormat = Literal["json", "csv", "sarif"]


def _results_to_dicts(results: list[ScanResult]) -> list[dict]:
    rows = []
    for result in results:
        for match in result.matches:
            rows.append(
                {
                    "file": result.path,
                    "line": match.line_number,
                    "rule_id": match.pattern.id,
                    "severity": match.severity.value,
                    "message": match.pattern.message,
                    "snippet": match.line.rstrip(),
                }
            )
    return rows


def export_json(results: list[ScanResult]) -> str:
    """Serialise results as a JSON array."""
    return json.dumps(_results_to_dicts(results), indent=2)


def export_csv(results: list[ScanResult]) -> str:
    """Serialise results as CSV with a header row."""
    fieldnames = ["file", "line", "rule_id", "severity", "message", "snippet"]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, lineterminator="\n")
    writer.writeheader()
    writer.writerows(_results_to_dicts(results))
    return buf.getvalue()


def export_sarif(results: list[ScanResult]) -> str:
    """Serialise results as a minimal SARIF 2.1.0 document."""
    sarif_results = []
    for result in results:
        for match in result.matches:
            sarif_results.append(
                {
                    "ruleId": match.pattern.id,
                    "level": _sarif_level(match.severity.value),
                    "message": {"text": match.pattern.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": result.path},
                                "region": {"startLine": match.line_number},
                            }
                        }
                    ],
                }
            )
    doc = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "shellsieve", "version": "1.0.0", "rules": []}},
                "results": sarif_results,
            }
        ],
    }
    return json.dumps(doc, indent=2)


def _sarif_level(severity: str) -> str:
    mapping = {"error": "error", "warning": "warning", "info": "note", "style": "note"}
    return mapping.get(severity.lower(), "warning")


def export(results: list[ScanResult], fmt: ExportFormat) -> str:
    """Dispatch to the appropriate exporter."""
    if fmt == "json":
        return export_json(results)
    if fmt == "csv":
        return export_csv(results)
    if fmt == "sarif":
        return export_sarif(results)
    raise ValueError(f"Unsupported export format: {fmt!r}")
