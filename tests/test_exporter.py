"""Tests for shellsieve.exporter."""

from __future__ import annotations

import csv
import io
import json

import pytest

from shellsieve.exporter import export, export_csv, export_json, export_sarif
from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match, ScanResult


def _make_pattern(
    pid: str = "SC001",
    message: str = "Unsafe pattern",
    severity: Severity = Severity.WARNING,
) -> Pattern:
    import re
    return Pattern(id=pid, regex=re.compile(r"eval"), message=message, severity=severity, tags=["injection"])


def _make_match(line: str = "eval $input", lineno: int = 5, pattern: Pattern | None = None) -> Match:
    return Match(line=line, line_number=lineno, pattern=pattern or _make_pattern())


def _make_result(path: str = "script.sh", matches: list[Match] | None = None) -> ScanResult:
    return ScanResult(path=path, matches=matches or [])


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def test_export_json_empty_results():
    output = export_json([])
    assert json.loads(output) == []


def test_export_json_contains_expected_keys():
    result = _make_result(matches=[_make_match()])
    rows = json.loads(export_json([result]))
    assert len(rows) == 1
    row = rows[0]
    assert row["file"] == "script.sh"
    assert row["line"] == 5
    assert row["rule_id"] == "SC001"
    assert row["severity"] == "warning"


def test_export_json_multiple_matches():
    matches = [_make_match(lineno=i) for i in range(1, 4)]
    result = _make_result(matches=matches)
    rows = json.loads(export_json([result]))
    assert len(rows) == 3


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

def test_export_csv_has_header():
    output = export_csv([])
    reader = csv.DictReader(io.StringIO(output))
    assert set(reader.fieldnames or []) >= {"file", "line", "rule_id", "severity"}


def test_export_csv_row_values():
    result = _make_result(matches=[_make_match()])
    output = export_csv([result])
    reader = csv.DictReader(io.StringIO(output))
    rows = list(reader)
    assert len(rows) == 1
    assert rows[0]["rule_id"] == "SC001"
    assert rows[0]["file"] == "script.sh"


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

def test_export_sarif_schema_version():
    doc = json.loads(export_sarif([]))
    assert doc["version"] == "2.1.0"


def test_export_sarif_result_structure():
    result = _make_result(matches=[_make_match()])
    doc = json.loads(export_sarif([result]))
    sarif_results = doc["runs"][0]["results"]
    assert len(sarif_results) == 1
    r = sarif_results[0]
    assert r["ruleId"] == "SC001"
    assert r["level"] == "warning"
    assert r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "script.sh"


def test_export_sarif_error_severity():
    pattern = _make_pattern(severity=Severity.ERROR)
    result = _make_result(matches=[_make_match(pattern=pattern)])
    doc = json.loads(export_sarif([result]))
    assert doc["runs"][0]["results"][0]["level"] == "error"


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def test_export_dispatches_json():
    output = export([], "json")
    assert json.loads(output) == []


def test_export_dispatches_csv():
    output = export([], "csv")
    assert "rule_id" in output


def test_export_dispatches_sarif():
    output = export([], "sarif")
    assert json.loads(output)["version"] == "2.1.0"


def test_export_raises_on_unknown_format():
    with pytest.raises(ValueError, match="Unsupported export format"):
        export([], "xml")  # type: ignore[arg-type]
