"""Tests for shellsieve.annotator."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from shellsieve.annotator import AnnotatedLine, annotate_result, annotate_results
from shellsieve.patterns import Severity
from shellsieve.scanner import Match, ScanResult


def _make_pattern(pid: str = "SC001", severity: str = "warning", message: str = "test msg"):
    p = MagicMock()
    p.id = pid
    p.severity = Severity(severity)
    p.message = message
    return p


def _make_match(lineno: int = 1, col: int = 0, snippet: str = "x", pid: str = "SC001") -> Match:
    pattern = _make_pattern(pid)
    return Match(pattern=pattern, lineno=lineno, col=col, snippet=snippet)


def _make_result(path: str = "script.sh", lines=None, matches=None) -> ScanResult:
    r = MagicMock(spec=ScanResult)
    r.path = path
    r.lines = lines or []
    r.matches = matches or []
    return r


def test_annotated_line_no_issues():
    aline = AnnotatedLine(lineno=1, text="echo hello")
    assert not aline.has_issues
    assert aline.highest_severity is None


def test_annotated_line_with_matches():
    m = _make_match(lineno=1)
    aline = AnnotatedLine(lineno=1, text="echo $x", matches=[m])
    assert aline.has_issues
    assert aline.highest_severity == "warning"


def test_highest_severity_prefers_error():
    m_warn = _make_match(lineno=1, pid="SC001")
    m_err = _make_match(lineno=1, pid="SC002")
    m_err.pattern.severity = Severity("error")
    aline = AnnotatedLine(lineno=1, text="bad", matches=[m_warn, m_err])
    assert aline.highest_severity == "error"


def test_annotate_result_creates_one_line_per_source_line():
    result = _make_result(lines=["line one", "line two", "line three"], matches=[])
    af = annotate_result(result)
    assert len(af.lines) == 3
    assert af.lines[0].lineno == 1
    assert af.lines[2].lineno == 3


def test_annotate_result_attaches_matches_to_correct_line():
    m = _make_match(lineno=2)
    result = _make_result(lines=["safe", "bad $x", "safe"], matches=[m])
    af = annotate_result(result)
    assert not af.lines[0].has_issues
    assert af.lines[1].has_issues
    assert af.lines[1].matches[0] is m
    assert not af.lines[2].has_issues


def test_annotate_result_multiple_matches_same_line():
    m1 = _make_match(lineno=1, pid="SC001")
    m2 = _make_match(lineno=1, pid="SC002")
    result = _make_result(lines=["bad line"], matches=[m1, m2])
    af = annotate_result(result)
    assert len(af.lines[0].matches) == 2


def test_issue_lines_filters_correctly():
    m = _make_match(lineno=2)
    result = _make_result(lines=["ok", "bad", "ok"], matches=[m])
    af = annotate_result(result)
    assert len(af.issue_lines) == 1
    assert af.issue_lines[0].lineno == 2


def test_annotate_results_returns_one_per_result():
    r1 = _make_result(path="a.sh", lines=["x"], matches=[])
    r2 = _make_result(path="b.sh", lines=["y", "z"], matches=[])
    annotated = annotate_results([r1, r2])
    assert len(annotated) == 2
    assert annotated[0].path == "a.sh"
    assert annotated[1].path == "b.sh"
    assert len(annotated[1].lines) == 2


def test_annotate_empty_result():
    result = _make_result(lines=[], matches=[])
    af = annotate_result(result)
    assert af.lines == []
    assert af.issue_lines == []
