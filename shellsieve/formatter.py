"""Output formatters for scan results."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import List

from shellsieve.scanner import ScanResult, Match
from shellsieve.fixer import Fix


class Formatter(ABC):
    """Base class for all output formatters."""

    @abstractmethod
    def format(self, results: List[ScanResult]) -> str:  # noqa: A003
        """Render *results* as a string."""


class TextFormatter(Formatter):
    """Human-readable plain-text output, optionally including fix suggestions."""

    def __init__(self, show_fixes: bool = False) -> None:
        self.show_fixes = show_fixes

    def format(self, results: List[ScanResult]) -> str:  # noqa: A003
        lines: list[str] = []
        for result in results:
            if not result.has_issues():
                lines.append(f"{result.path}: no issues found")
                continue
            for match in result.matches:
                lines.append(
                    f"{result.path}:{match.lineno}:{match.col}  "
                    f"[{match.pattern.id}] {match.pattern.description}  "
                    f"({match.severity.name})"
                )
                if self.show_fixes:
                    from shellsieve.fixer import suggest_fix

                    fix = suggest_fix(match, match.snippet)
                    if fix is not None:
                        lines.append(str(fix))
        return "\n".join(lines)


class JSONFormatter(Formatter):
    """Machine-readable JSON output."""

    def format(self, results: List[ScanResult]) -> str:  # noqa: A003
        payload = []
        for result in results:
            payload.append(
                {
                    "path": str(result.path),
                    "issues": [
                        {
                            "id": m.pattern.id,
                            "description": m.pattern.description,
                            "severity": m.severity.name,
                            "line": m.lineno,
                            "col": m.col,
                            "snippet": m.snippet,
                        }
                        for m in result.matches
                    ],
                }
            )
        return json.dumps(payload, indent=2)


def get_formatter(name: str, **kwargs) -> Formatter:
    """Return a :class:`Formatter` by *name* (``'text'`` or ``'json'``)."""
    formatters: dict[str, type[Formatter]] = {
        "text": TextFormatter,
        "json": JSONFormatter,
    }
    cls = formatters.get(name.lower())
    if cls is None:
        raise ValueError(f"Unknown formatter {name!r}. Choose from: {list(formatters)}.")
    return cls(**kwargs)
