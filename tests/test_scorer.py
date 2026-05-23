"""Tests for shellsieve.scorer."""
from __future__ import annotations

import pytest

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match, ScanResult
from shellsieve.scorer import (
    FileScore,
    ScoreReport,
    _score_matches,
    score_result,
    build_score_report,
)


def _make_pattern(pid: str, severity: Severity) -> Pattern:
    import re
    return Pattern(
        id=pid,
        description="test",
        regex=re.compile(r"x"),
        severity=severity,
        tags=[],
        fix_hint=None,
    )


def _make_match(pid: str, severity: Severity) -> Match:
    return Match(
        pattern=_make_pattern(pid, severity),
        line=1,
        column=0,
        source_line="x",
    )


def _make_result(path: str, matches: list) -> ScanResult:
    return ScanResult(path=path, matches=matches)


# --- _score_matches ---

def test_score_matches_empty():
    score, breakdown = _score_matches([])
    assert score == 0
    assert all(v == 0 for v in breakdown.values())


def test_score_matches_single_error():
    score, breakdown = _score_matches([_make_match("SC001", Severity.ERROR)])
    assert score == 10
    assert breakdown["error"] == 10


def test_score_matches_warning_weight():
    score, _ = _score_matches([_make_match("SC002", Severity.WARNING)])
    assert score == 3


def test_score_matches_info_weight():
    score, _ = _score_matches([_make_match("SC003", Severity.INFO)])
    assert score == 1


def test_score_matches_mixed():
    matches = [
        _make_match("SC001", Severity.ERROR),
        _make_match("SC002", Severity.WARNING),
        _make_match("SC003", Severity.INFO),
    ]
    score, breakdown = _score_matches(matches)
    assert score == 14
    assert breakdown["error"] == 10
    assert breakdown["warning"] == 3
    assert breakdown["info"] == 1


# --- FileScore.risk_label ---

def test_risk_label_clean():
    fs = FileScore(path="a.sh", score=0, match_count=0)
    assert fs.risk_label == "clean"


def test_risk_label_low():
    fs = FileScore(path="a.sh", score=5, match_count=1)
    assert fs.risk_label == "low"


def test_risk_label_medium():
    fs = FileScore(path="a.sh", score=15, match_count=2)
    assert fs.risk_label == "medium"


def test_risk_label_high():
    fs = FileScore(path="a.sh", score=40, match_count=5)
    assert fs.risk_label == "high"


# --- score_result ---

def test_score_result_no_matches():
    result = _make_result("clean.sh", [])
    fs = score_result(result)
    assert fs.score == 0
    assert fs.match_count == 0
    assert fs.path == "clean.sh"


def test_score_result_with_matches():
    matches = [_make_match("SC001", Severity.ERROR)] * 2
    result = _make_result("bad.sh", matches)
    fs = score_result(result)
    assert fs.score == 20
    assert fs.match_count == 2


# --- build_score_report ---

def test_build_score_report_empty():
    report = build_score_report([])
    assert report.total_score == 0
    assert report.highest_risk_file is None


def test_build_score_report_total():
    r1 = _make_result("a.sh", [_make_match("SC001", Severity.ERROR)])
    r2 = _make_result("b.sh", [_make_match("SC002", Severity.WARNING)])
    report = build_score_report([r1, r2])
    assert report.total_score == 13


def test_build_score_report_highest_risk():
    r1 = _make_result("a.sh", [_make_match("SC001", Severity.ERROR)] * 3)
    r2 = _make_result("b.sh", [_make_match("SC002", Severity.INFO)])
    report = build_score_report([r1, r2])
    assert report.highest_risk_file is not None
    assert report.highest_risk_file.path == "a.sh"


def test_as_dict_structure():
    r = _make_result("x.sh", [_make_match("SC001", Severity.WARNING)])
    report = build_score_report([r])
    d = report.as_dict()
    assert "total_score" in d
    assert "files" in d
    assert d["files"][0]["path"] == "x.sh"
    assert "risk_label" in d["files"][0]
