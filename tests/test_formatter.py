"""Tests for shellsieve.formatter."""

from __future__ import annotations

import json
import pathlib
import pytest

from shellsieve.formatter import TextFormatter, JSONFormatter, get_formatter
from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match, ScanResult


def _make_pattern(pid: str = "TST001", message: str = "test issue") -> Pattern:
    import re
    return Pattern(
        id=pid,
        severity=Severity.HIGH,
        regex=re.compile(r"eval"),
        message=message,
        description="A test pattern.",
    )


def _make_result(path: str = "script.sh", matches: list[Match] | None = None) -> ScanResult:
    return ScanResult(path=pathlib.Path(path), matches=matches or [])


def _make_match(line_number: int = 3, line_text: str = "  eval $input") -> Match:
    return Match(pattern=_make_pattern(), line_number=line_number, line_text=line_text)


# --- TextFormatter ---

def test_text_formatter_no_issues():
    result = _make_result(matches=[])
    output = TextFormatter().format(result)
    assert "no issues found" in output
    assert "script.sh" in output


def test_text_formatter_with_match():
    match = _make_match(line_number=7, line_text="eval $x")
    result = _make_result(matches=[match])
    output = TextFormatter().format(result)
    assert "7" in output
    assert "TST001" in output
    assert "eval $x" in output
    assert "HIGH" in output


def test_text_formatter_multiple_matches():
    matches = [_make_match(line_number=i) for i in range(1, 4)]
    result = _make_result(matches=matches)
    output = TextFormatter().format(result)
    assert output.count("TST001") == 3


# --- JSONFormatter ---

def test_json_formatter_structure():
    match = _make_match(line_number=2, line_text="eval bad")
    result = _make_result(path="foo.sh", matches=[match])
    raw = JSONFormatter().format(result)
    data = json.loads(raw)
    assert data["path"] == "foo.sh"
    assert data["issue_count"] == 1
    issue = data["issues"][0]
    assert issue["line"] == 2
    assert issue["id"] == "TST001"
    assert issue["severity"] == "HIGH"


def test_json_formatter_no_issues():
    result = _make_result(matches=[])
    data = json.loads(JSONFormatter().format(result))
    assert data["issue_count"] == 0
    assert data["issues"] == []


# --- get_formatter ---

def test_get_formatter_text():
    fmt = get_formatter("text")
    assert isinstance(fmt, TextFormatter)


def test_get_formatter_json():
    fmt = get_formatter("json")
    assert isinstance(fmt, JSONFormatter)


def test_get_formatter_unknown_raises():
    with pytest.raises(ValueError, match="Unknown formatter"):
        get_formatter("xml")
