"""Tests for shellsieve.tag_cmd."""

from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from shellsieve.tag_cmd import build_tag_parser, run_tag


def _write_script(tmp_path: Path, content: str) -> Path:
    p = tmp_path / "script.sh"
    p.write_text(content)
    return p


def _make_args(files: list[str], category: str | None = None, no_colour: bool = False) -> argparse.Namespace:
    return argparse.Namespace(files=files, category=category, no_colour=no_colour)


def test_build_tag_parser_registers_subcommand():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers()
    p = build_tag_parser(sub)
    assert p is not None


def test_run_tag_missing_file_returns_2(tmp_path: Path):
    args = _make_args([str(tmp_path / "nonexistent.sh")])
    assert run_tag(args) == 2


def test_run_tag_clean_script_returns_0(tmp_path: Path):
    script = _write_script(tmp_path, "#!/bin/bash\necho hello\n")
    args = _make_args([str(script)])
    result = run_tag(args)
    assert result == 0


def test_run_tag_with_category_filter_returns_0(tmp_path: Path, capsys):
    script = _write_script(tmp_path, "#!/bin/bash\necho hello\n")
    args = _make_args([str(script)], category="injection")
    result = run_tag(args)
    assert result == 0


def test_run_tag_no_colour_flag_accepted(tmp_path: Path):
    script = _write_script(tmp_path, "#!/bin/bash\necho hello\n")
    args = _make_args([str(script)], no_colour=True)
    # Should not raise
    result = run_tag(args)
    assert isinstance(result, int)
