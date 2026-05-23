"""Tests for shellsieve.linter."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from shellsieve.linter import lint_files, FileLintResult, LintReport
from shellsieve.patterns import Severity
from shellsieve.scanner import Match


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_script(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content))
    return p


# ---------------------------------------------------------------------------
# FileLintResult
# ---------------------------------------------------------------------------

def test_file_lint_result_ok_when_no_matches(tmp_path):
    p = tmp_path / "clean.sh"
    p.write_text("echo hello\n")
    result = FileLintResult(path=p, matches=[])
    assert result.ok is True


def test_file_lint_result_not_ok_with_matches(tmp_path, _make_match):
    p = tmp_path / "bad.sh"
    p.write_text("eval $cmd\n")
    result = FileLintResult(path=p, matches=[_make_match(Severity.ERROR)])
    assert result.ok is False


def test_file_lint_result_not_ok_with_error(tmp_path):
    p = tmp_path / "ghost.sh"
    result = FileLintResult(path=p, matches=[], error="file not found")
    assert result.ok is False


def test_error_count_and_warning_count(tmp_path, _make_match):
    p = tmp_path / "mixed.sh"
    p.write_text("")
    matches = [
        _make_match(Severity.ERROR),
        _make_match(Severity.ERROR),
        _make_match(Severity.WARNING),
    ]
    result = FileLintResult(path=p, matches=matches)
    assert result.error_count == 2
    assert result.warning_count == 1


# ---------------------------------------------------------------------------
# LintReport
# ---------------------------------------------------------------------------

def test_lint_report_totals(tmp_path, _make_match):
    p1 = tmp_path / "a.sh"
    p2 = tmp_path / "b.sh"
    r1 = FileLintResult(path=p1, matches=[_make_match(Severity.ERROR)])
    r2 = FileLintResult(path=p2, matches=[_make_match(Severity.WARNING)])
    report = LintReport(results=[r1, r2])
    assert report.total_errors == 1
    assert report.total_warnings == 1
    assert len(report.failed_files) == 2
    assert len(report.passed_files) == 0


def test_lint_report_as_dict(tmp_path, _make_match):
    p = tmp_path / "x.sh"
    r = FileLintResult(path=p, matches=[_make_match(Severity.ERROR)])
    report = LintReport(results=[r])
    d = report.as_dict()
    assert d["total_files"] == 1
    assert d["failed_files"] == 1
    assert d["total_errors"] == 1


# ---------------------------------------------------------------------------
# lint_files integration
# ---------------------------------------------------------------------------

def test_lint_files_clean_script(tmp_path):
    p = _write_script(tmp_path, "clean.sh", "echo hello\n")
    report = lint_files([p])
    assert report.total_errors == 0
    assert len(report.passed_files) == 1


def test_lint_files_missing_file(tmp_path):
    p = tmp_path / "missing.sh"
    report = lint_files([p])
    assert len(report.results) == 1
    assert report.results[0].error is not None


def test_lint_files_multiple_paths(tmp_path):
    p1 = _write_script(tmp_path, "a.sh", "echo a\n")
    p2 = _write_script(tmp_path, "b.sh", "echo b\n")
    report = lint_files([p1, p2])
    assert len(report.results) == 2


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def _make_match():
    from shellsieve.patterns import Pattern

    def factory(severity: Severity) -> Match:
        pat = Pattern(
            id="SC001",
            description="test",
            pattern=r"eval",
            severity=severity,
            tags=[],
            fix_hint=None,
        )
        return Match(pattern=pat, line=1, column=0, text="eval $x")

    return factory
