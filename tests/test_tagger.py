"""Tests for shellsieve.tagger."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from shellsieve.scanner import Match
from shellsieve.tagger import (
    TaggedMatch,
    _infer_categories,
    group_by_category,
    tag_matches,
)


def _make_pattern(tags: list[str] | None = None):
    p = MagicMock()
    p.id = "SC001"
    p.tags = tags or []
    return p


def _make_match(tags: list[str] | None = None) -> Match:
    return Match(
        path=Path("script.sh"),
        line_number=1,
        line="echo $VAR",
        pattern=_make_pattern(tags),
    )


def test_infer_categories_known_tag():
    m = _make_match(tags=["injection"])
    cats = _infer_categories(m)
    assert cats == ["Code Injection"]


def test_infer_categories_multiple_known_tags():
    m = _make_match(tags=["quoting", "eval"])
    cats = _infer_categories(m)
    assert "Unsafe Quoting" in cats
    assert "Dynamic Evaluation" in cats


def test_infer_categories_unknown_tag_falls_back():
    m = _make_match(tags=["unknown_tag"])
    cats = _infer_categories(m)
    assert cats == ["Uncategorised"]


def test_infer_categories_no_tags_falls_back():
    m = _make_match(tags=[])
    cats = _infer_categories(m)
    assert cats == ["Uncategorised"]


def test_tag_matches_wraps_all():
    matches = [_make_match(["injection"]), _make_match(["quoting"])]
    tagged = tag_matches(matches)
    assert len(tagged) == 2
    assert all(isinstance(t, TaggedMatch) for t in tagged)


def test_tagged_match_primary_category():
    tm = TaggedMatch(match=_make_match(["env"]), categories=["Environment Variable Risk", "Unsafe Quoting"])
    assert tm.primary_category == "Environment Variable Risk"


def test_tagged_match_primary_category_empty():
    tm = TaggedMatch(match=_make_match(), categories=[])
    assert tm.primary_category == "Uncategorised"


def test_group_by_category_single_group():
    tagged = tag_matches([_make_match(["injection"]), _make_match(["injection"])])
    groups = group_by_category(tagged)
    assert "Code Injection" in groups
    assert len(groups["Code Injection"]) == 2


def test_group_by_category_multiple_groups():
    tagged = tag_matches([_make_match(["injection"]), _make_match(["quoting"])])
    groups = group_by_category(tagged)
    assert len(groups) == 2


def test_group_by_category_empty():
    groups = group_by_category([])
    assert groups == {}
