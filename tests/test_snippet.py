"""Tests for shellsieve.snippet."""

from __future__ import annotations

from pathlib import Path

import pytest

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match
from shellsieve.snippet import Snippet, extract_snippet, extract_snippets


def _make_pattern(pid: str = "SC001") -> Pattern:
    import re
    return Pattern(
        id=pid,
        regex=re.compile(r"eval"),
        message="Avoid eval",
        severity=Severity.ERROR,
        tags=["injection"],
        fix=None,
    )


def _make_match(lineno: int = 3, col: int = 1) -> Match:
    return Match(pattern=_make_pattern(), lineno=lineno, col=col, line="eval $x")


def _write_script(tmp_path: Path, lines: list[str]) -> Path:
    p = tmp_path / "script.sh"
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


def test_extract_snippet_basic(tmp_path: Path) -> None:
    script = _write_script(tmp_path, ["#!/bin/bash", "x=1", "eval $x", "echo done", "exit 0"])
    match = _make_match(lineno=3)
    snippet = extract_snippet(script, match, context=1)
    assert snippet is not None
    assert snippet.highlight_lineno == 3
    assert snippet.lines[snippet.highlight_index] == "eval $x"


def test_extract_snippet_context_clipped_at_top(tmp_path: Path) -> None:
    script = _write_script(tmp_path, ["eval $x", "echo hi", "echo bye"])
    match = _make_match(lineno=1)
    snippet = extract_snippet(script, match, context=3)
    assert snippet is not None
    assert snippet.start_lineno == 1
    assert snippet.highlight_index == 0


def test_extract_snippet_context_clipped_at_bottom(tmp_path: Path) -> None:
    script = _write_script(tmp_path, ["echo hi", "echo bye", "eval $x"])
    match = _make_match(lineno=3)
    snippet = extract_snippet(script, match, context=5)
    assert snippet is not None
    assert snippet.lines[-1] == "eval $x"


def test_extract_snippet_returns_none_for_missing_file(tmp_path: Path) -> None:
    match = _make_match(lineno=1)
    result = extract_snippet(tmp_path / "ghost.sh", match, context=2)
    assert result is None


def test_extract_snippet_returns_none_for_out_of_range(tmp_path: Path) -> None:
    script = _write_script(tmp_path, ["echo hi"])
    match = _make_match(lineno=99)
    result = extract_snippet(script, match, context=2)
    assert result is None


def test_extract_snippets_multiple(tmp_path: Path) -> None:
    lines = ["#!/bin/bash", "eval $a", "echo mid", "eval $b", "exit 0"]
    script = _write_script(tmp_path, lines)
    matches = [_make_match(lineno=2), _make_match(lineno=4)]
    snippets = extract_snippets(script, matches, context=1)
    assert len(snippets) == 2
    assert snippets[0].highlight_lineno == 2
    assert snippets[1].highlight_lineno == 4


def test_extract_snippets_skips_bad_matches(tmp_path: Path) -> None:
    script = _write_script(tmp_path, ["echo hi"])
    matches = [_make_match(lineno=999)]
    snippets = extract_snippets(script, matches, context=2)
    assert snippets == []
