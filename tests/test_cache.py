"""Tests for shellsieve.cache."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shellsieve.cache import (
    _file_digest,
    is_cached,
    invalidate,
    load_cache,
    mark_cached,
    save_cache,
)


@pytest.fixture()
def script(tmp_path: Path) -> Path:
    p = tmp_path / "script.sh"
    p.write_text("#!/bin/bash\necho hello\n", encoding="utf-8")
    return p


@pytest.fixture()
def cache_file(tmp_path: Path) -> Path:
    return tmp_path / ".shellsieve_cache.json"


def test_file_digest_is_hex_string(script: Path) -> None:
    digest = _file_digest(script)
    assert isinstance(digest, str)
    assert len(digest) == 64  # sha256 hex


def test_file_digest_changes_on_content_change(script: Path) -> None:
    d1 = _file_digest(script)
    script.write_text("#!/bin/bash\necho world\n", encoding="utf-8")
    d2 = _file_digest(script)
    assert d1 != d2


def test_load_cache_returns_empty_when_missing(tmp_path: Path) -> None:
    result = load_cache(tmp_path / "nonexistent.json")
    assert result == {}


def test_load_cache_returns_empty_on_corrupt_file(tmp_path: Path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text("not json!", encoding="utf-8")
    assert load_cache(bad) == {}


def test_save_and_load_round_trip(cache_file: Path) -> None:
    data = {"key": {"mtime": 1234.0, "size": 42, "digest": "abc"}}
    save_cache(data, cache_file)
    loaded = load_cache(cache_file)
    assert loaded == data


def test_is_cached_false_for_unknown_file(script: Path) -> None:
    assert not is_cached(script, {})


def test_mark_then_is_cached(script: Path) -> None:
    cache: dict = {}
    mark_cached(script, cache)
    assert is_cached(script, cache)


def test_is_cached_false_after_content_change(script: Path) -> None:
    cache: dict = {}
    mark_cached(script, cache)
    script.write_text("#!/bin/bash\nrm -rf /\n", encoding="utf-8")
    assert not is_cached(script, cache)


def test_invalidate_removes_entry(script: Path) -> None:
    cache: dict = {}
    mark_cached(script, cache)
    assert is_cached(script, cache)
    invalidate(script, cache)
    assert not is_cached(script, cache)


def test_invalidate_noop_on_missing(script: Path) -> None:
    cache: dict = {}
    # Should not raise
    invalidate(script, cache)
    assert cache == {}
