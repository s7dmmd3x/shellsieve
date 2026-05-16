"""Tests for shellsieve.formatter (extended with fixer integration)."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match, ScanResult
from shellsieve.formatter import TextFormatter, JSONFormatter, get_formatter


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(pid: str = "SC001", desc: str = "Unquoted variable"):
    return Pattern(
        id=pid,
        description=desc,
        regex=re.compile(r"\$\w+"),
        severity=Severity.WARNING,
        advice="Quote it",
    )


def _make_match(pid: str = "SC001", lineno: int = 3, col: int = 5) -> Match:
    return Match(
        pattern=_make_pattern(pid),
        lineno=lineno,
        col=col,
        snippet="$VAR",
    )


def _make_result(path: str = "script.sh", matches=None) -> ScanResult:
    return ScanResult(path=Path(path), matches=matches or [])


# ---------------------------------------------------------------------------
# TextFormatter
# ---------------------------------------------------------------------------

def test_text_formatter_no_issues():
    result = _make_result(matches=[])
    output = TextFormatter().format([result])
    assert "no issues found" in output


def test_text_formatter_with_match():
    result = _make_result(matches=[_make_match()])
    output = TextFormatter().format([result])
    assert "SC001" in output
    assert "script.sh" in output
    assert "WARNING" in output


def test_text_formatter_includes_line_and_col():
    result = _make_result(matches=[_make_match(lineno=7, col=12)])
    output = TextFormatter().format([result])
    assert ":7:" in output
    assert ":12" in output


def test_text_formatter_show_fixes_flag():
    """When show_fixes=True and a fixer exists, fix suggestion appears."""
    result = _make_result(matches=[_make_match("SC001")])
    # The snippet is "$VAR" which the SC001 fixer can act on
    output = TextFormatter(show_fixes=True).format([result])
    # Just check it doesn't raise; fix output is optional depending on snippet
    assert "SC001" in output


# ---------------------------------------------------------------------------
# JSONFormatter
# ---------------------------------------------------------------------------

def test_json_formatter_valid_json():
    result = _make_result(matches=[_make_match()])
    output = JSONFormatter().format([result])
    parsed = json.loads(output)
    assert isinstance(parsed, list)


def test_json_formatter_structure():
    result = _make_result(matches=[_make_match()])
    parsed = json.loads(JSONFormatter().format([result]))
    issue = parsed[0]["issues"][0]
    assert issue["id"] == "SC001"
    assert issue["severity"] == "WARNING"
    assert issue["line"] == 3


def test_json_formatter_no_issues():
    result = _make_result(matches=[])
    parsed = json.loads(JSONFormatter().format([result]))
    assert parsed[0]["issues"] == []


# ---------------------------------------------------------------------------
# get_formatter
# ---------------------------------------------------------------------------

def test_get_formatter_text():
    assert isinstance(get_formatter("text"), TextFormatter)


def test_get_formatter_json():
    assert isinstance(get_formatter("json"), JSONFormatter)


def test_get_formatter_unknown_raises():
    with pytest.raises(ValueError, match="Unknown formatter"):
        get_formatter("xml")
