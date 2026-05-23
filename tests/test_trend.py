"""Tests for shellsieve.trend."""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from shellsieve.trend import (
    TrendEntry,
    TrendReport,
    load_trend,
    save_trend,
    record_entry,
    make_entry,
)


def _make_entry(**kwargs) -> TrendEntry:
    defaults = dict(timestamp=1_000_000.0, total_issues=3, error_count=1, warning_count=2, file_count=5, scanned_files=5)
    defaults.update(kwargs)
    return TrendEntry(**defaults)


def test_entry_as_dict_round_trip():
    e = _make_entry()
    d = e.as_dict()
    restored = TrendEntry.from_dict(d)
    assert restored.total_issues == e.total_issues
    assert restored.timestamp == e.timestamp


def test_trend_report_latest_none_when_empty():
    assert TrendReport().latest() is None


def test_trend_report_latest_returns_last():
    e1 = _make_entry(timestamp=1.0)
    e2 = _make_entry(timestamp=2.0)
    r = TrendReport(entries=[e1, e2])
    assert r.latest() is e2


def test_delta_none_when_single_entry():
    r = TrendReport(entries=[_make_entry()])
    assert r.delta() is None


def test_delta_computes_difference():
    e1 = _make_entry(total_issues=4, error_count=2, warning_count=2)
    e2 = _make_entry(total_issues=6, error_count=3, warning_count=3)
    r = TrendReport(entries=[e1, e2])
    d = r.delta()
    assert d["total_issues"] == 2
    assert d["error_count"] == 1
    assert d["warning_count"] == 1


def test_delta_negative_when_improved():
    e1 = _make_entry(total_issues=10, error_count=5, warning_count=5)
    e2 = _make_entry(total_issues=4, error_count=2, warning_count=2)
    r = TrendReport(entries=[e1, e2])
    d = r.delta()
    assert d["total_issues"] == -6


def test_save_and_load_round_trip(tmp_path):
    path = tmp_path / "trend.json"
    entries = [_make_entry(timestamp=float(i)) for i in range(3)]
    report = TrendReport(entries=entries)
    save_trend(report, path)
    loaded = load_trend(path)
    assert len(loaded.entries) == 3
    assert loaded.entries[0].timestamp == 0.0


def test_load_returns_empty_when_missing(tmp_path):
    r = load_trend(tmp_path / "nonexistent.json")
    assert r.entries == []


def test_record_entry_appends():
    r = TrendReport(entries=[_make_entry()])
    new_e = _make_entry(total_issues=99)
    r2 = record_entry(r, new_e)
    assert len(r2.entries) == 2
    assert r2.entries[-1].total_issues == 99


def test_record_entry_caps_at_max():
    entries = [_make_entry(timestamp=float(i)) for i in range(10)]
    r = TrendReport(entries=entries)
    new_e = _make_entry(timestamp=999.0)
    r2 = record_entry(r, new_e, max_entries=5)
    assert len(r2.entries) == 5
    assert r2.entries[-1].timestamp == 999.0


def test_make_entry_from_stats_dict():
    stats = {"total_issues": 7, "error_count": 3, "warning_count": 4, "file_count": 2, "scanned_files": 2}
    e = make_entry(stats)
    assert e.total_issues == 7
    assert e.error_count == 3
    assert e.file_count == 2
    assert e.timestamp > 0


def test_make_entry_defaults_missing_keys():
    e = make_entry({})
    assert e.total_issues == 0
    assert e.error_count == 0
