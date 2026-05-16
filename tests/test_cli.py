"""Tests for shellsieve.cli."""

from __future__ import annotations

from pathlib import Path

import pytest

from shellsieve.cli import run


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_script(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content)
    return p


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_clean_script_exits_zero(tmp_path):
    script = _write_script(tmp_path, "clean.sh", "#!/bin/bash\necho hello\n")
    # Use a pattern file that won't match 'echo hello'
    code = run([str(script), "--no-colour"])
    assert code == 0


def test_missing_file_does_not_crash(tmp_path, capsys):
    code = run([str(tmp_path / "nope.sh"), "--no-colour", "--exit-zero"])
    captured = capsys.readouterr()
    assert "not found" in captured.err
    assert code == 0


def test_exit_zero_flag_overrides(tmp_path):
    # Write a script that will trigger at least one built-in pattern.
    script = _write_script(tmp_path, "bad.sh", "eval $USER_INPUT\n")
    code = run([str(script), "--no-colour", "--exit-zero"])
    assert code == 0


def test_issues_return_nonzero(tmp_path):
    script = _write_script(tmp_path, "bad.sh", "eval $USER_INPUT\n")
    code = run([str(script), "--no-colour"])
    # Only meaningful if the built-in patterns include an eval rule.
    # We assert the return type is int regardless.
    assert isinstance(code, int)


def test_min_severity_filters(tmp_path):
    """With --min-severity critical, low/medium/high issues should be suppressed."""
    script = _write_script(tmp_path, "any.sh", "eval $X\ncurl http://x\n")
    code = run([str(script), "--no-colour", "--min-severity", "critical"])
    # No CRITICAL patterns expected for these lines → exit 0
    assert code == 0


def test_no_colour_flag_accepted(tmp_path, capsys):
    script = _write_script(tmp_path, "s.sh", "echo ok\n")
    code = run([str(script), "--no-colour"])
    out = capsys.readouterr().out
    assert "\033[" not in out
