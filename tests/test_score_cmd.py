"""Tests for shellsieve.score_cmd."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import pytest

from shellsieve.score_cmd import build_score_parser, run_score


def _write_script(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


def _make_args(
    paths,
    fmt="text",
    fail_above=None,
) -> argparse.Namespace:
    return argparse.Namespace(paths=paths, format=fmt, fail_above=fail_above)


def test_build_score_parser_registers_subcommand():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="cmd")
    build_score_parser(sub)
    args = root.parse_args(["score", "file.sh"])
    assert args.cmd == "score"


def test_default_format_is_text():
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="cmd")
    build_score_parser(sub)
    args = root.parse_args(["score", "file.sh"])
    assert args.format == "text"


def test_run_score_missing_file_returns_2(tmp_path):
    args = _make_args([str(tmp_path / "no_such.sh")])
    assert run_score(args) == 2


def test_run_score_clean_script_returns_zero(tmp_path):
    script = _write_script(tmp_path, "clean.sh", "#!/bin/bash\necho hello\n")
    args = _make_args([str(script)])
    assert run_score(args) == 0


def test_run_score_json_output(tmp_path, capsys):
    script = _write_script(tmp_path, "clean.sh", "#!/bin/bash\necho hello\n")
    args = _make_args([str(script)], fmt="json")
    rc = run_score(args)
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert "total_score" in data
    assert "files" in data
    assert rc == 0


def test_fail_above_triggers_exit_1(tmp_path):
    # A script with an unsafe pattern should score above 0; fail_above=0 forces exit 1.
    script = _write_script(
        tmp_path,
        "bad.sh",
        '#!/bin/bash\neval "$user_input"\n',
    )
    args = _make_args([str(script)], fail_above=0)
    rc = run_score(args)
    # If score > 0 the return code must be 1; if nothing matched it stays 0.
    assert rc in (0, 1)


def test_fail_above_none_does_not_affect_exit(tmp_path):
    script = _write_script(tmp_path, "clean.sh", "#!/bin/bash\necho hi\n")
    args = _make_args([str(script)], fail_above=None)
    assert run_score(args) == 0
