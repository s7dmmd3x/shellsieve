"""Tests for shellsieve.differ."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch, MagicMock

import pytest

from shellsieve.differ import DiffResult, diff_matches, format_diff
from shellsieve.scanner import Match
from shellsieve.patterns import Severity


def _make_pattern(pid: str = "SC001", desc: str = "test pattern"):
    return SimpleNamespace(id=pid, description=desc, severity=Severity.HIGH, regex=None, tags=[])


def _make_match(pid: str = "SC001", line: int = 1, path: str = "script.sh") -> Match:
    p = _make_pattern(pid)
    return Match(pattern=p, line_number=line, line_text="echo $VAR", path=path)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# DiffResult
# ---------------------------------------------------------------------------

def test_diff_result_has_new_issues_true():
    dr = DiffResult(added=[_make_match()])
    assert dr.has_new_issues is True


def test_diff_result_has_new_issues_false():
    dr = DiffResult()
    assert dr.has_new_issues is False


def test_diff_result_summary_format():
    dr = DiffResult(added=[_make_match()], removed=[_make_match("SC002")], unchanged=[_make_match("SC003")])
    s = dr.summary()
    assert "+1" in s
    assert "-1" in s
    assert "=1" in s


# ---------------------------------------------------------------------------
# diff_matches
# ---------------------------------------------------------------------------

def test_diff_empty_lists():
    result = diff_matches([], [])
    assert result.added == []
    assert result.removed == []
    assert result.unchanged == []


def test_diff_detects_new_match():
    before: list = []
    after = [_make_match()]
    result = diff_matches(before, after)
    assert len(result.added) == 1
    assert result.removed == []


def test_diff_detects_removed_match():
    before = [_make_match()]
    after: list = []
    result = diff_matches(before, after)
    assert len(result.removed) == 1
    assert result.added == []


def test_diff_unchanged_match():
    m = _make_match()
    result = diff_matches([m], [m])
    assert len(result.unchanged) == 1
    assert result.added == []
    assert result.removed == []


def test_diff_distinguishes_by_line():
    m1 = _make_match(line=1)
    m2 = _make_match(line=2)
    result = diff_matches([m1], [m2])
    assert len(result.added) == 1
    assert len(result.removed) == 1


# ---------------------------------------------------------------------------
# format_diff
# ---------------------------------------------------------------------------

def test_format_diff_no_new_issues_message():
    dr = DiffResult()
    out = format_diff(dr, colour=False)
    assert "No new issues" in out


def test_format_diff_shows_added_line():
    dr = DiffResult(added=[_make_match()])
    out = format_diff(dr, colour=False)
    assert "SC001" in out
    assert "+" in out


def test_format_diff_colour_disabled_no_escape():
    dr = DiffResult(added=[_make_match()])
    out = format_diff(dr, colour=False)
    assert "\033[" not in out


def test_format_diff_colour_enabled_has_escape():
    dr = DiffResult(added=[_make_match()])
    out = format_diff(dr, colour=True)
    assert "\033[" in out
