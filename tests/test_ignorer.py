"""Tests for shellsieve.ignorer."""

from pathlib import Path

import pytest

from shellsieve.ignorer import (
    build_ignore_patterns,
    filter_paths,
    matches_ignore_pattern,
)


# ---------------------------------------------------------------------------
# matches_ignore_pattern
# ---------------------------------------------------------------------------


def test_matches_git_directory():
    assert matches_ignore_pattern(".git/config", [".git/*"]) is True


def test_no_match_returns_false():
    assert matches_ignore_pattern("scripts/deploy.sh", [".git/*"]) is False


def test_matches_by_basename():
    """Pattern without a slash should still match deep paths via basename."""
    assert matches_ignore_pattern("some/deep/path/file.bak", ["*.bak"]) is True


def test_matches_multiple_patterns_first_wins():
    patterns = ["*.bak", "node_modules/*"]
    assert matches_ignore_pattern("node_modules/lib/script.sh", patterns) is True


def test_does_not_match_similar_extension():
    assert matches_ignore_pattern("file.backup", ["*.bak"]) is False


# ---------------------------------------------------------------------------
# build_ignore_patterns
# ---------------------------------------------------------------------------


def test_build_includes_defaults():
    patterns = build_ignore_patterns()
    assert ".git/*" in patterns
    assert "*.swp" in patterns


def test_build_merges_extras():
    patterns = build_ignore_patterns(["vendor/*", "dist/*"])
    assert "vendor/*" in patterns
    assert "dist/*" in patterns
    assert ".git/*" in patterns


def test_build_with_none_extra():
    patterns = build_ignore_patterns(None)
    assert isinstance(patterns, list)
    assert len(patterns) > 0


# ---------------------------------------------------------------------------
# filter_paths
# ---------------------------------------------------------------------------


def test_filter_removes_ignored():
    paths = [
        "scripts/deploy.sh",
        ".git/hooks/pre-commit",
        "node_modules/bin/run.sh",
        "src/build.sh",
    ]
    result = filter_paths(paths)
    result_strs = [str(p) for p in result]
    assert "scripts/deploy.sh" in result_strs
    assert "src/build.sh" in result_strs
    assert not any(".git" in s for s in result_strs)
    assert not any("node_modules" in s for s in result_strs)


def test_filter_returns_path_objects():
    result = filter_paths(["foo.sh"])
    assert all(isinstance(p, Path) for p in result)


def test_filter_with_extra_patterns():
    paths = ["vendor/helper.sh", "src/main.sh"]
    result = filter_paths(paths, extra_patterns=["vendor/*"])
    result_strs = [str(p) for p in result]
    assert "src/main.sh" in result_strs
    assert "vendor/helper.sh" not in result_strs


def test_filter_empty_input():
    assert filter_paths([]) == []
