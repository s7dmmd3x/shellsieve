"""Tests for shellsieve.suppression."""

from __future__ import annotations

import pytest

from shellsieve.suppression import (
    filter_suppressed,
    is_suppressed,
    parse_suppressed_ids,
)


# ---------------------------------------------------------------------------
# parse_suppressed_ids
# ---------------------------------------------------------------------------

def test_parse_single_id():
    line = 'eval "$x"  # shellsieve: disable=SS003'
    assert parse_suppressed_ids(line) == frozenset({"SS003"})


def test_parse_multiple_ids():
    line = 'rm -rf /  # shellsieve: disable=SS001, SS002'
    assert parse_suppressed_ids(line) == frozenset({"SS001", "SS002"})


def test_parse_no_annotation():
    assert parse_suppressed_ids("echo hello") == frozenset()


def test_parse_is_case_insensitive():
    line = 'foo  # shellsieve: disable=ss005'
    assert parse_suppressed_ids(line) == frozenset({"SS005"})


def test_parse_extra_whitespace():
    line = 'bar  # shellsieve:  disable = SS010 , SS011 '
    result = parse_suppressed_ids(line)
    assert "SS010" in result
    assert "SS011" in result


# ---------------------------------------------------------------------------
# is_suppressed
# ---------------------------------------------------------------------------

def test_is_suppressed_exact_match():
    assert is_suppressed("SS003", frozenset({"SS003"}))


def test_is_suppressed_not_in_set():
    assert not is_suppressed("SS004", frozenset({"SS003"}))


def test_is_suppressed_wildcard():
    assert is_suppressed("SS999", frozenset({"*"}))


def test_is_suppressed_empty_set():
    assert not is_suppressed("SS001", frozenset())


# ---------------------------------------------------------------------------
# filter_suppressed  (uses lightweight stubs)
# ---------------------------------------------------------------------------

class _FakePattern:
    def __init__(self, pid: str):
        self.id = pid


class _FakeMatch:
    def __init__(self, pid: str):
        self.pattern = _FakePattern(pid)


def test_filter_removes_suppressed_match():
    matches = [_FakeMatch("SS003"), _FakeMatch("SS004")]
    line = 'eval "$x"  # shellsieve: disable=SS003'
    result = filter_suppressed(matches, line)
    assert len(result) == 1
    assert result[0].pattern.id == "SS004"


def test_filter_keeps_all_when_no_annotation():
    matches = [_FakeMatch("SS001"), _FakeMatch("SS002")]
    result = filter_suppressed(matches, "echo hello")
    assert len(result) == 2


def test_filter_removes_all_when_all_suppressed():
    matches = [_FakeMatch("SS001"), _FakeMatch("SS002")]
    line = 'cmd  # shellsieve: disable=SS001,SS002'
    assert filter_suppressed(matches, line) == []
