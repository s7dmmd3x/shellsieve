"""Tests for shellsieve.profiler."""

from __future__ import annotations

import pytest

from shellsieve.patterns import Pattern, Severity
from shellsieve.scanner import Match
from shellsieve.profiler import (
    build_profile,
    format_profile,
    PatternProfile,
    ScanProfile,
)


def _make_pattern(pid: str, description: str = "desc") -> Pattern:
    import re

    return Pattern(
        id=pid,
        description=description,
        regex=re.compile(r"x"),
        severity=Severity.LOW,
        tags=["test"],
        fix_hint=None,
    )


def _make_match(pid: str, line: int = 1, description: str = "desc") -> Match:
    pat = _make_pattern(pid, description)
    return Match(pattern=pat, line=line, column=0, source_line="x")


def test_build_profile_empty():
    profile = build_profile({})
    assert isinstance(profile, ScanProfile)
    assert profile.profiles == []


def test_build_profile_single_file_single_pattern():
    matches = [_make_match("SC001"), _make_match("SC001", line=2)]
    profile = build_profile({"script.sh": matches})
    assert len(profile.profiles) == 1
    p = profile.profiles[0]
    assert p.pattern_id == "SC001"
    assert p.hit_count == 2
    assert p.files_affected == 1


def test_build_profile_multiple_patterns():
    matches = [_make_match("SC001"), _make_match("SC002")]
    profile = build_profile({"a.sh": matches})
    ids = {p.pattern_id for p in profile.profiles}
    assert ids == {"SC001", "SC002"}


def test_build_profile_counts_files_correctly():
    profile = build_profile(
        {
            "a.sh": [_make_match("SC001")],
            "b.sh": [_make_match("SC001")],
            "c.sh": [_make_match("SC002")],
        }
    )
    by_id = {p.pattern_id: p for p in profile.profiles}
    assert by_id["SC001"].files_affected == 2
    assert by_id["SC001"].hit_count == 2
    assert by_id["SC002"].files_affected == 1


def test_scan_profile_top_returns_sorted():
    profiles = [
        PatternProfile("SC003", "c", 1, 1),
        PatternProfile("SC001", "a", 10, 2),
        PatternProfile("SC002", "b", 5, 1),
    ]
    sp = ScanProfile(profiles=profiles)
    top = sp.top(2)
    assert [p.pattern_id for p in top] == ["SC001", "SC002"]


def test_scan_profile_top_respects_n():
    profiles = [PatternProfile(f"SC00{i}", "d", i, 1) for i in range(10)]
    sp = ScanProfile(profiles=profiles)
    assert len(sp.top(3)) == 3


def test_pattern_profile_as_dict():
    p = PatternProfile("SC001", "Unquoted var", 4, 2)
    d = p.as_dict()
    assert d["pattern_id"] == "SC001"
    assert d["hit_count"] == 4
    assert d["files_affected"] == 2


def test_format_profile_no_matches():
    sp = ScanProfile(profiles=[])
    output = format_profile(sp)
    assert "no matches" in output


def test_format_profile_shows_rank_and_id():
    matches = [_make_match("SC001", description="Unquoted variable")]
    profile = build_profile({"script.sh": matches})
    output = format_profile(profile, top_n=5)
    assert "SC001" in output
    assert "1." in output
    assert "Unquoted variable" in output
