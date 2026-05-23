"""Tests for shellsieve.snippet_formatter."""

from __future__ import annotations

import re
from pathlib import Path

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match
from shellsieve.snippet import Snippet
from shellsieve.snippet_formatter import TextSnippetFormatter


def _make_pattern(pid: str = "SC001") -> Pattern:
    import re as _re
    return Pattern(
        id=pid,
        regex=_re.compile(r"eval"),
        message="Avoid eval",
        severity=Severity.ERROR,
        tags=["injection"],
        fix=None,
    )


def _make_snippet(lineno: int = 3) -> Snippet:
    match = Match(pattern=_make_pattern(), lineno=lineno, col=1, line="eval $x")
    return Snippet(
        match=match,
        lines=["x=1", "eval $x", "echo done"],
        start_lineno=lineno - 1,
        highlight_index=1,
    )


def test_render_contains_pattern_id() -> None:
    fmt = TextSnippetFormatter(colour=False)
    out = fmt.render(Path("script.sh"), [_make_snippet()])
    assert "SC001" in out


def test_render_contains_file_path() -> None:
    fmt = TextSnippetFormatter(colour=False)
    out = fmt.render(Path("myscript.sh"), [_make_snippet()])
    assert "myscript.sh" in out


def test_render_contains_highlighted_line() -> None:
    fmt = TextSnippetFormatter(colour=False)
    out = fmt.render(Path("s.sh"), [_make_snippet(lineno=3)])
    assert "eval $x" in out


def test_render_multiple_snippets() -> None:
    fmt = TextSnippetFormatter(colour=False)
    s1 = _make_snippet(lineno=3)
    s2 = _make_snippet(lineno=3)
    out = fmt.render(Path("s.sh"), [s1, s2])
    # Both occurrences of the pattern message should appear
    assert out.count("Avoid eval") == 2


def test_render_no_colour_has_no_ansi() -> None:
    fmt = TextSnippetFormatter(colour=False)
    out = fmt.render(Path("s.sh"), [_make_snippet()])
    assert "\033[" not in out


def test_render_with_colour_has_ansi() -> None:
    fmt = TextSnippetFormatter(colour=True)
    out = fmt.render(Path("s.sh"), [_make_snippet()])
    assert "\033[" in out


def test_render_empty_snippets_shows_header_only() -> None:
    fmt = TextSnippetFormatter(colour=False)
    out = fmt.render(Path("clean.sh"), [])
    assert "clean.sh" in out
    assert "SC001" not in out
