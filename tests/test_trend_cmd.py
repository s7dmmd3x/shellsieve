"""Tests for shellsieve.trend_cmd."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from shellsieve.trend_cmd import build_trend_parser, run_trend


def _write_script(tmp_path: Path, name: str = "script.sh", content: str = "#!/bin/bash\necho hello\n") -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _make_args(tmp_path: Path, paths, **kwargs) -> argparse.Namespace:
    defaults = {
        "trend_file": str(tmp_path / ".trend.json"),
        "no_record": False,
        "last": 10,
    }
    defaults.update(kwargs)
    return argparse.Namespace(paths=[str(p) for p in paths], **defaults)


def test_build_trend_parser_registers_subcommand():
    parser = argparse.ArgumentParser()
    subs = parser.add_subparsers()
    build_trend_parser(subs)
    args = parser.parse_args(["trend", "script.sh"])
    assert args.paths == ["script.sh"]


def test_run_trend_missing_file_returns_2(tmp_path):
    args = _make_args(tmp_path, [tmp_path / "ghost.sh"])
    assert run_trend(args) == 2


def test_run_trend_clean_script_returns_0(tmp_path):
    script = _write_script(tmp_path)
    args = _make_args(tmp_path, [script])
    result = run_trend(args)
    assert result == 0


def test_run_trend_records_entry(tmp_path):
    script = _write_script(tmp_path)
    trend_file = tmp_path / ".trend.json"
    args = _make_args(tmp_path, [script], trend_file=str(trend_file))
    run_trend(args)
    assert trend_file.exists()
    data = json.loads(trend_file.read_text())
    assert len(data["entries"]) == 1


def test_run_trend_no_record_does_not_write(tmp_path):
    script = _write_script(tmp_path)
    trend_file = tmp_path / ".trend.json"
    args = _make_args(tmp_path, [script], trend_file=str(trend_file), no_record=True)
    run_trend(args)
    assert not trend_file.exists()


def test_run_trend_accumulates_entries(tmp_path):
    script = _write_script(tmp_path)
    trend_file = tmp_path / ".trend.json"
    for _ in range(3):
        args = _make_args(tmp_path, [script], trend_file=str(trend_file))
        run_trend(args)
    data = json.loads(trend_file.read_text())
    assert len(data["entries"]) == 3
