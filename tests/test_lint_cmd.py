"""Tests for shellsieve.lint_cmd."""
from __future__ import annotations

import json
import textwrap
from argparse import ArgumentParser
from pathlib import Path
from unittest.mock import patch

import pytest

from shellsieve.lint_cmd import build_lint_parser, run_lint


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _write_script(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content))
    return p


def _make_args(paths, fmt="text", summary=False, exit_zero=False):
    from argparse import Namespace
    return Namespace(paths=paths, fmt=fmt, summary=summary, exit_zero=exit_zero)


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------

def test_build_lint_parser_registers_subcommand():
    root = ArgumentParser()
    sub = root.add_subparsers()
    build_lint_parser(sub)
    args = root.parse_args(["lint", "/tmp/x.sh"])
    assert args.paths == [Path("/tmp/x.sh")]


def test_default_format_is_text():
    root = ArgumentParser()
    sub = root.add_subparsers()
    build_lint_parser(sub)
    args = root.parse_args(["lint", "/tmp/x.sh"])
    assert args.fmt == "text"


# ---------------------------------------------------------------------------
# run_lint exit codes
# ---------------------------------------------------------------------------

def test_run_lint_clean_script_returns_zero(tmp_path):
    p = _write_script(tmp_path, "clean.sh", "echo hello\n")
    args = _make_args([p])
    assert run_lint(args) == 0


def test_run_lint_missing_file_returns_zero(tmp_path):
    """Missing file is reported as error but no lint matches → exit 0."""
    p = tmp_path / "ghost.sh"
    args = _make_args([p])
    code = run_lint(args)
    assert code == 0


def test_run_lint_exit_zero_flag(tmp_path):
    """--exit-zero always returns 0 regardless of findings."""
    p = _write_script(tmp_path, "bad.sh", "eval $cmd\n")
    args = _make_args([p], exit_zero=True)
    assert run_lint(args) == 0


def test_run_lint_summary_flag_does_not_crash(tmp_path, capsys):
    p = _write_script(tmp_path, "ok.sh", "echo hi\n")
    args = _make_args([p], summary=True)
    run_lint(args)
    captured = capsys.readouterr()
    assert "Summary" in captured.out


def test_run_lint_json_format_does_not_crash(tmp_path):
    p = _write_script(tmp_path, "ok.sh", "echo hi\n")
    args = _make_args([p], fmt="json")
    code = run_lint(args)
    assert code == 0
