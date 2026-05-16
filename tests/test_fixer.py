"""Tests for shellsieve.fixer."""

from __future__ import annotations

import re
from types import SimpleNamespace

import pytest

from shellsieve.fixer import Fix, suggest_fix, suggest_fixes_for_lines
from shellsieve.scanner import Match


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_pattern(pid: str, regex: str = r"\$\w+"):
    from shellsieve.patterns import Severity, Pattern
    return Pattern(
        id=pid,
        description="test pattern",
        regex=re.compile(regex),
        severity=Severity.WARNING,
        advice="fix it",
    )


def _make_match(pid: str, lineno: int = 1, col: int = 0) -> Match:
    pattern = _make_pattern(pid)
    return Match(pattern=pattern, lineno=lineno, col=col, snippet="$VAR")


# ---------------------------------------------------------------------------
# suggest_fix
# ---------------------------------------------------------------------------

def test_suggest_fix_returns_fix_for_known_pattern():
    match = _make_match("SC001")
    fix = suggest_fix(match, "echo $VAR\n")
    assert fix is not None
    assert isinstance(fix, Fix)


def test_suggest_fix_returns_none_for_unknown_pattern():
    match = _make_match("SC999")
    fix = suggest_fix(match, "echo $VAR\n")
    assert fix is None


def test_suggest_fix_sc001_quotes_variable():
    match = _make_match("SC001")
    fix = suggest_fix(match, "echo $HOME\n")
    assert fix is not None
    assert '"$HOME"' in fix.fixed_line


def test_suggest_fix_sc004_upgrades_brackets():
    match = _make_match("SC004")
    fix = suggest_fix(match, "if [ -z $1 ]; then\n")
    assert fix is not None
    assert "[[" in fix.fixed_line


def test_fix_str_contains_before_and_after():
    match = _make_match("SC001")
    fix = suggest_fix(match, "echo $NAME\n")
    assert fix is not None
    text = str(fix)
    assert "Before:" in text
    assert "After:" in text


def test_suggest_fix_returns_none_when_pattern_does_not_match_line():
    """Regex in fixer doesn't match the given line → no fix."""
    match = _make_match("SC004")
    # Line has no [ ] construct
    fix = suggest_fix(match, "echo hello\n")
    assert fix is None


# ---------------------------------------------------------------------------
# suggest_fixes_for_lines
# ---------------------------------------------------------------------------

def test_suggest_fixes_for_lines_returns_list():
    m = _make_match("SC001", lineno=1)
    lines = ["echo $USER\n"]
    fixes = suggest_fixes_for_lines({1: [m]}, lines)
    assert len(fixes) == 1


def test_suggest_fixes_for_lines_skips_unknown_patterns():
    m = _make_match("SC999", lineno=1)
    lines = ["echo $USER\n"]
    fixes = suggest_fixes_for_lines({1: [m]}, lines)
    assert fixes == []


def test_suggest_fixes_for_lines_handles_out_of_range_lineno():
    m = _make_match("SC001", lineno=99)
    lines = ["echo $USER\n"]
    # Should not raise; line will be empty string → no regex match → no fix
    fixes = suggest_fixes_for_lines({99: [m]}, lines)
    assert fixes == []
