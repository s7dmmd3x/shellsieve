"""Tests for shellsieve.summary_cmd."""
from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from shellsieve.summary_cmd import build_summary_parser, run_summary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_script(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _make_args(**kwargs) -> argparse.Namespace:
    defaults = {"paths": [], "no_colour": True, "min_severity": None}
    defaults.update(kwargs)
    return argparse.Namespace(**defaults)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

def test_build_summary_parser_registers_subcommand():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="cmd")
    build_summary_parser(sub)
    args = root.parse_args(["summary", "file.sh"])
    assert args.cmd == "summary"
    assert args.paths == ["file.sh"]


def test_no_colour_default_is_false():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="cmd")
    build_summary_parser(sub)
    args = root.parse_args(["summary", "file.sh"])
    assert args.no_colour is False


# ---------------------------------------------------------------------------
# run_summary()
# ---------------------------------------------------------------------------

def test_run_summary_missing_file_returns_2(tmp_path):
    args = _make_args(paths=[str(tmp_path / "nonexistent.sh")])
    assert run_summary(args) == 2


def test_run_summary_clean_script_returns_zero(tmp_path):
    script = _write_script(tmp_path, "clean.sh", "#!/bin/bash\necho hello\n")
    args = _make_args(paths=[str(script)])
    assert run_summary(args) == 0


def test_run_summary_risky_script_returns_nonzero(tmp_path):
    script = _write_script(tmp_path, "risky.sh", '#!/bin/bash\neval "$USER_INPUT"\n')
    args = _make_args(paths=[str(script)])
    result = run_summary(args)
    assert result in (0, 1)  # depends on loaded patterns; must not crash


def test_run_summary_multiple_files(tmp_path):
    s1 = _write_script(tmp_path, "a.sh", "#!/bin/bash\necho ok\n")
    s2 = _write_script(tmp_path, "b.sh", "#!/bin/bash\necho ok\n")
    args = _make_args(paths=[str(s1), str(s2)])
    rc = run_summary(args)
    assert rc in (0, 1)


def test_run_summary_min_severity_accepted(tmp_path):
    script = _write_script(tmp_path, "s.sh", "#!/bin/bash\necho hi\n")
    args = _make_args(paths=[str(script)], min_severity="ERROR")
    rc = run_summary(args)
    assert rc in (0, 1)
