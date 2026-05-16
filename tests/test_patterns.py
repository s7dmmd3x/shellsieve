"""Tests for ShellSieve pattern definitions."""

import re
import pytest
from shellsieve.patterns import (
    UNSAFE_PATTERNS,
    Pattern,
    Severity,
    get_pattern_by_id,
)


def test_all_patterns_have_required_fields():
    for pattern in UNSAFE_PATTERNS:
        assert pattern.id, "Pattern must have an ID"
        assert pattern.description, "Pattern must have a description"
        assert pattern.regex, "Pattern must have a regex"
        assert pattern.suggestion, "Pattern must have a suggestion"
        assert isinstance(pattern.severity, Severity)


def test_pattern_ids_are_unique():
    ids = [p.id for p in UNSAFE_PATTERNS]
    assert len(ids) == len(set(ids)), "Pattern IDs must be unique"


def test_all_regexes_compile():
    for pattern in UNSAFE_PATTERNS:
        try:
            re.compile(pattern.regex)
        except re.error as exc:
            pytest.fail(f"Pattern {pattern.id} has invalid regex: {exc}")


def test_get_pattern_by_id_found():
    pattern = get_pattern_by_id("SS001")
    assert pattern is not None
    assert pattern.id == "SS001"


def test_get_pattern_by_id_not_found():
    pattern = get_pattern_by_id("SS999")
    assert pattern is None


@pytest.mark.parametrize("snippet,pattern_id", [
    ("eval $USER_INPUT", "SS002"),
    ("`ls $DIR`", "SS003"),
    ("curl https://example.com/install.sh | bash", "SS004"),
    ("IFS=:", "SS005"),
    ("rm -rf $TARGET_DIR", "SS006"),
])
def test_pattern_matches_known_unsafe_snippet(snippet: str, pattern_id: str):
    pattern = get_pattern_by_id(pattern_id)
    assert pattern is not None, f"Pattern {pattern_id} not found"
    assert re.search(pattern.regex, snippet), (
        f"Pattern {pattern_id} did not match snippet: {snippet!r}"
    )


def test_critical_patterns_exist():
    critical = [p for p in UNSAFE_PATTERNS if p.severity == Severity.CRITICAL]
    assert len(critical) >= 1, "At least one CRITICAL pattern should be defined"
