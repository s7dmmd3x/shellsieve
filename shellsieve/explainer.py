"""Explain why a pattern matched and what risk it poses."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from shellsieve.patterns import Pattern
from shellsieve.scanner import Match

# Per-pattern prose explanations keyed by pattern id.
_EXPLANATIONS: dict[str, str] = {
    "SC001": (
        "Unquoted variable expansions are subject to word splitting and "
        "glob expansion by the shell. An attacker who controls the variable "
        "value can inject extra arguments or cause unintended file matches."
    ),
    "SC002": (
        "Using 'eval' on untrusted input allows arbitrary command execution. "
        "Any data that reaches this call can be interpreted as shell code."
    ),
    "SC003": (
        "Backtick command substitution is an older syntax that nests poorly "
        "and can obscure injection points. Prefer $() for clarity and safety."
    ),
    "SC004": (
        "Sourcing a file with '.' or 'source' executes its contents in the "
        "current shell context. If the path is user-controlled this is "
        "equivalent to arbitrary code execution."
    ),
    "SC005": (
        "curl piped directly to bash fetches and immediately executes remote "
        "code without any integrity check. A compromised server or MITM "
        "attacker can run arbitrary commands on the host."
    ),
}

_FALLBACK = (
    "This pattern has been flagged as potentially unsafe. Review the matched "
    "line carefully and consult the shellsieve documentation for guidance."
)


@dataclass(frozen=True)
class Explanation:
    pattern_id: str
    pattern_description: str
    severity: str
    matched_text: str
    lineno: int
    file_path: str
    prose: str
    reference_url: Optional[str]

    def as_dict(self) -> dict:
        return {
            "pattern_id": self.pattern_id,
            "pattern_description": self.pattern_description,
            "severity": self.severity,
            "matched_text": self.matched_text,
            "lineno": self.lineno,
            "file_path": self.file_path,
            "prose": self.prose,
            "reference_url": self.reference_url,
        }


def explain_match(match: Match, file_path: str = "<unknown>") -> Explanation:
    """Return a human-readable explanation for a single Match."""
    prose = _EXPLANATIONS.get(match.pattern.id, _FALLBACK)
    ref = getattr(match.pattern, "reference_url", None)
    return Explanation(
        pattern_id=match.pattern.id,
        pattern_description=match.pattern.description,
        severity=match.severity.name,
        matched_text=match.line.rstrip(),
        lineno=match.lineno,
        file_path=file_path,
        prose=prose,
        reference_url=ref,
    )


def explain_matches(matches: list[Match], file_path: str = "<unknown>") -> list[Explanation]:
    """Return explanations for every match in *matches*."""
    return [explain_match(m, file_path) for m in matches]
