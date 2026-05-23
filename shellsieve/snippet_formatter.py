"""Formatters for Snippet output."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Sequence

from shellsieve.snippet import Snippet

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_DIM = "\033[2m"


class SnippetFormatter(ABC):
    @abstractmethod
    def render(self, path: Path, snippets: Sequence[Snippet]) -> str: ...


class TextSnippetFormatter(SnippetFormatter):
    def __init__(self, colour: bool = True) -> None:
        self._colour = colour

    def _c(self, code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if self._colour else text

    def render(self, path: Path, snippets: Sequence[Snippet]) -> str:
        parts: List[str] = []
        header = self._c(_BOLD, f"==> {path}")
        parts.append(header)

        for snippet in snippets:
            m = snippet.match
            rule_line = (
                self._c(_CYAN, f"  [{m.pattern.id}]") +
                f" {m.pattern.message}  "
                + self._c(_DIM, f"({m.pattern.severity.name})")
            )
            parts.append(rule_line)

            for i, line in enumerate(snippet.lines):
                lineno = snippet.start_lineno + i
                prefix = f"  {lineno:4d} | "
                if i == snippet.highlight_index:
                    parts.append(self._c(_RED, prefix + line))
                else:
                    parts.append(self._c(_DIM, prefix + line))

            parts.append("")

        return "\n".join(parts)
