"""Unsafe shell pattern definitions for ShellSieve static analyzer."""

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Pattern:
    id: str
    description: str
    severity: Severity
    regex: str
    suggestion: str
    tags: List[str] = field(default_factory=list)


UNSAFE_PATTERNS: List[Pattern] = [
    Pattern(
        id="SS001",
        description="Unquoted variable expansion",
        severity=Severity.MEDIUM,
        regex=r'(?<!["\'])\$[A-Za-z_][A-Za-z0-9_]*(?!["\'])(?=\s|;|\||&|$)',
        suggestion="Quote variable: \"$VAR\" to prevent word splitting and glob expansion.",
        tags=["injection", "word-splitting"],
    ),
    Pattern(
        id="SS002",
        description="Use of eval with variable input",
        severity=Severity.CRITICAL,
        regex=r'\beval\s+.*\$',
        suggestion="Avoid eval with user-controlled variables; use safer alternatives.",
        tags=["injection", "eval"],
    ),
    Pattern(
        id="SS003",
        description="Command substitution with unquoted variable",
        severity=Severity.HIGH,
        regex=r'`[^`]*\$[A-Za-z_][A-Za-z0-9_]*[^`]*`',
        suggestion="Quote variables inside command substitution: `cmd \"$VAR\"`.",
        tags=["injection", "command-substitution"],
    ),
    Pattern(
        id="SS004",
        description="Curl piped directly to shell",
        severity=Severity.CRITICAL,
        regex=r'curl\s+[^|]+\|\s*(bash|sh|zsh)',
        suggestion="Download and inspect scripts before executing them.",
        tags=["remote-execution", "supply-chain"],
    ),
    Pattern(
        id="SS005",
        description="Use of $IFS manipulation",
        severity=Severity.MEDIUM,
        regex=r'IFS\s*=',
        suggestion="Restoring IFS after modification is critical; document intent clearly.",
        tags=["ifs", "word-splitting"],
    ),
    Pattern(
        id="SS006",
        description="Unsafe use of rm -rf with variable",
        severity=Severity.HIGH,
        regex=r'rm\s+-[rRfF]{1,4}\s+.*\$',
        suggestion="Validate and quote path variables before passing to rm -rf.",
        tags=["destructive", "path-traversal"],
    ),
]


def get_pattern_by_id(pattern_id: str) -> Optional[Pattern]:
    """Return a pattern by its ID, or None if not found."""
    return next((p for p in UNSAFE_PATTERNS if p.id == pattern_id), None)


def get_patterns_by_tag(tag: str) -> List[Pattern]:
    """Return all patterns that include the given tag.

    Args:
        tag: The tag string to filter patterns by (e.g. "injection", "destructive").

    Returns:
        A list of Pattern instances whose tags include the specified tag.
    """
    return [p for p in UNSAFE_PATTERNS if tag in p.tags]


def get_patterns_by_severity(severity: Severity) -> List[Pattern]:
    """Return all patterns matching the given severity level.

    Args:
        severity: A Severity enum value to filter patterns by.

    Returns:
        A list of Pattern instances with the specified severity.
    """
    return [p for p in UNSAFE_PATTERNS if p.severity == severity]
