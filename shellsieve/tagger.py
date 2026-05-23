"""Automatic tag inference for scan matches based on pattern metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence

from shellsieve.scanner import Match

# Map pattern id prefixes / tags to human-readable category labels
_CATEGORY_MAP: Dict[str, str] = {
    "injection": "Code Injection",
    "quoting": "Unsafe Quoting",
    "redirect": "Unsafe Redirect",
    "eval": "Dynamic Evaluation",
    "env": "Environment Variable Risk",
    "path": "Path Traversal",
    "priv": "Privilege Escalation",
}


@dataclass
class TaggedMatch:
    """A Match decorated with inferred category labels."""

    match: Match
    categories: List[str] = field(default_factory=list)

    @property
    def primary_category(self) -> str:
        return self.categories[0] if self.categories else "Uncategorised"


def _infer_categories(match: Match) -> List[str]:
    """Return category labels for *match* based on its pattern tags."""
    categories: List[str] = []
    tags = match.pattern.tags if match.pattern.tags else []
    for tag in tags:
        label = _CATEGORY_MAP.get(tag.lower())
        if label and label not in categories:
            categories.append(label)
    return categories or ["Uncategorised"]


def tag_matches(matches: Sequence[Match]) -> List[TaggedMatch]:
    """Wrap each match with inferred category information."""
    return [TaggedMatch(match=m, categories=_infer_categories(m)) for m in matches]


def group_by_category(tagged: Sequence[TaggedMatch]) -> Dict[str, List[TaggedMatch]]:
    """Group *tagged* matches by their primary category."""
    groups: Dict[str, List[TaggedMatch]] = {}
    for tm in tagged:
        groups.setdefault(tm.primary_category, []).append(tm)
    return groups
