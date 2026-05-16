"""Tests for shellsieve.baseline."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from shellsieve.baseline import (
    DEFAULT_BASELINE_FILE,
    filter_baseline,
    load_baseline,
    save_baseline,
)
from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match


def _make_pattern(pid: str = "SS001") -> Pattern:
    import re
    return Pattern(
        id=pid,
        description="test pattern",
        regex=re.compile(r"eval"),
        severity=Severity.HIGH,
        advice="avoid eval",
    )


def _make_match(file: str = "script.sh", line_no: int = 1, pid: str = "SS001") -> Match:
    return Match(
        file=Path(file),
        line_no=line_no,
        line="eval $input",
        pattern=_make_pattern(pid),
    )


# ---------------------------------------------------------------------------
# save / load round-trip
# ---------------------------------------------------------------------------

def test_save_creates_json_file(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    matches = [_make_match()]
    save_baseline(matches, baseline_file)
    assert baseline_file.exists()
    data = json.loads(baseline_file.read_text())
    assert isinstance(data, list)
    assert len(data) == 1


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    baseline_file = tmp_path / "baseline.json"
    matches = [_make_match("a.sh", 3, "SS001"), _make_match("b.sh", 7, "SS002")]
    save_baseline(matches, baseline_file)
    loaded = load_baseline(baseline_file)
    assert len(loaded) == 2
    assert loaded[0]["file"] == "a.sh"
    assert loaded[1]["line_no"] == 7


def test_load_returns_empty_list_when_file_missing(tmp_path: Path) -> None:
    result = load_baseline(tmp_path / "nonexistent.json")
    assert result == []


def test_load_returns_empty_list_on_corrupt_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json{{{")
    result = load_baseline(bad)
    assert result == []


# ---------------------------------------------------------------------------
# filter_baseline
# ---------------------------------------------------------------------------

def test_filter_baseline_removes_known_matches() -> None:
    m = _make_match("script.sh", 5, "SS001")
    baseline = [{"file": "script.sh", "line_no": 5, "pattern_id": "SS001"}]
    result = filter_baseline([m], baseline)
    assert result == []


def test_filter_baseline_keeps_new_matches() -> None:
    m = _make_match("script.sh", 10, "SS002")
    baseline = [{"file": "script.sh", "line_no": 5, "pattern_id": "SS001"}]
    result = filter_baseline([m], baseline)
    assert result == [m]


def test_filter_baseline_empty_baseline_keeps_all() -> None:
    matches = [_make_match(), _make_match("other.sh", 2)]
    result = filter_baseline(matches, [])
    assert len(result) == 2


def test_filter_baseline_skips_malformed_entries() -> None:
    m = _make_match("script.sh", 1, "SS001")
    # entry missing 'pattern_id'
    baseline = [{"file": "script.sh", "line_no": 1}]
    result = filter_baseline([m], baseline)
    # malformed entry should not match anything
    assert result == [m]
