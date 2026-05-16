"""Output formatters for shellsieve scan results."""

from __future__ import annotations

import json
from typing import Protocol

from shellsieve.scanner import ScanResult


class Formatter(Protocol):
    """Protocol for result formatters."""

    def format(self, result: ScanResult) -> str:
        ...


class TextFormatter:
    """Human-readable plain-text formatter."""

    def format(self, result: ScanResult) -> str:
        if not result.has_issues():
            return f"{result.path}: no issues found\n"

        lines: list[str] = []
        for match in result.matches:
            lines.append(
                f"{result.path}:{match.line_number}: [{match.severity}] "
                f"{match.pattern.id} — {match.pattern.message}\n"
                f"  {match.line_text.rstrip()}"
            )
        return "\n".join(lines) + "\n"


class JSONFormatter:
    """Machine-readable JSON formatter."""

    def format(self, result: ScanResult) -> str:
        payload = {
            "path": str(result.path),
            "issue_count": len(result.matches),
            "issues": [
                {
                    "line": match.line_number,
                    "severity": match.severity,
                    "id": match.pattern.id,
                    "message": match.pattern.message,
                    "text": match.line_text.rstrip(),
                }
                for match in result.matches
            ],
        }
        return json.dumps(payload, indent=2)


FORMATTERS: dict[str, Formatter] = {
    "text": TextFormatter(),
    "json": JSONFormatter(),
}


def get_formatter(name: str) -> Formatter:
    """Return a formatter by name, defaulting to text."""
    if name not in FORMATTERS:
        raise ValueError(
            f"Unknown formatter {name!r}. Choices: {list(FORMATTERS)}"
        )
    return FORMATTERS[name]
