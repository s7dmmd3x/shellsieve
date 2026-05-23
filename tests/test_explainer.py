"""Tests for shellsieve.explainer."""
from __future__ import annotations

import types
from unittest.mock import MagicMock

import pytest

from shellsieve.explainer import (
    Explanation,
    _EXPLANATIONS,
    _FALLBACK,
    explain_match,
    explain_matches,
)
from shellsieve.patterns import Pattern, Severity


def _make_pattern(pid: str = "SC001", description: str = "Unquoted variable") -> Pattern:
    import re
    return Pattern(
        id=pid,
        description=description,
        regex=re.compile(r"\$[A-Za-z_]+"),
        severity=Severity.ERROR,
        tags=["injection"],
    )


def _make_match(pattern: Pattern, line: str = "echo $VAR", lineno: int = 3) -> MagicMock:
    m = MagicMock()
    m.pattern = pattern
    m.line = line
    m.lineno = lineno
    m.severity = pattern.severity
    return m


def test_explain_match_returns_explanation():
    pat = _make_pattern("SC001")
    match = _make_match(pat)
    exp = explain_match(match, file_path="test.sh")
    assert isinstance(exp, Explanation)


def test_explain_match_known_id_uses_custom_prose():
    pat = _make_pattern("SC001")
    match = _make_match(pat)
    exp = explain_match(match)
    assert exp.prose == _EXPLANATIONS["SC001"]


def test_explain_match_unknown_id_uses_fallback():
    pat = _make_pattern("SC999", description="Unknown pattern")
    match = _make_match(pat)
    exp = explain_match(match)
    assert exp.prose == _FALLBACK


def test_explain_match_fields_are_populated():
    pat = _make_pattern("SC002")
    match = _make_match(pat, line="eval $USER_INPUT", lineno=7)
    exp = explain_match(match, file_path="script.sh")
    assert exp.pattern_id == "SC002"
    assert exp.lineno == 7
    assert exp.file_path == "script.sh"
    assert exp.matched_text == "eval $USER_INPUT"
    assert exp.severity == "ERROR"


def test_explain_match_strips_trailing_newline():
    pat = _make_pattern("SC001")
    match = _make_match(pat, line="echo $VAR\n")
    exp = explain_match(match)
    assert not exp.matched_text.endswith("\n")


def test_explain_match_reference_url_none_when_absent():
    pat = _make_pattern("SC001")
    # Pattern dataclass may or may not carry reference_url; explainer must handle both.
    match = _make_match(pat)
    exp = explain_match(match)
    # Should not raise; value is either None or a string.
    assert exp.reference_url is None or isinstance(exp.reference_url, str)


def test_explain_matches_returns_one_per_match():
    pat = _make_pattern("SC001")
    matches = [_make_match(pat, lineno=i) for i in range(5)]
    explanations = explain_matches(matches, file_path="a.sh")
    assert len(explanations) == 5


def test_explain_matches_empty_input():
    assert explain_matches([]) == []


def test_as_dict_contains_required_keys():
    pat = _make_pattern("SC003")
    match = _make_match(pat)
    exp = explain_match(match, file_path="x.sh")
    d = exp.as_dict()
    for key in ("pattern_id", "pattern_description", "severity", "matched_text",
                "lineno", "file_path", "prose", "reference_url"):
        assert key in d, f"missing key: {key}"


def test_explanation_is_immutable():
    pat = _make_pattern("SC001")
    match = _make_match(pat)
    exp = explain_match(match)
    with pytest.raises((AttributeError, TypeError)):
        exp.prose = "hacked"  # type: ignore[misc]
