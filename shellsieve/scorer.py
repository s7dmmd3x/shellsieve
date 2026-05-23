"""Risk scorer: computes a numeric risk score for a scan result."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from shellsieve.scanner import Match, ScanResult
from shellsieve.patterns import Severity

# Weight assigned to each severity level.
_SEVERITY_WEIGHTS: dict[Severity, int] = {
    Severity.ERROR: 10,
    Severity.WARNING: 3,
    Severity.INFO: 1,
}


@dataclass
class FileScore:
    """Risk score for a single file."""

    path: str
    score: int
    match_count: int
    breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def risk_label(self) -> str:
        if self.score == 0:
            return "clean"
        if self.score < 10:
            return "low"
        if self.score < 30:
            return "medium"
        return "high"


@dataclass
class ScoreReport:
    """Aggregated risk scores across all scanned files."""

    file_scores: List[FileScore] = field(default_factory=list)

    @property
    def total_score(self) -> int:
        return sum(fs.score for fs in self.file_scores)

    @property
    def highest_risk_file(self) -> FileScore | None:
        if not self.file_scores:
            return None
        return max(self.file_scores, key=lambda fs: fs.score)

    def as_dict(self) -> dict:
        return {
            "total_score": self.total_score,
            "files": [
                {
                    "path": fs.path,
                    "score": fs.score,
                    "risk_label": fs.risk_label,
                    "match_count": fs.match_count,
                    "breakdown": fs.breakdown,
                }
                for fs in self.file_scores
            ],
        }


def _score_matches(matches: List[Match]) -> tuple[int, dict[str, int]]:
    """Return (total_score, breakdown_by_severity) for a list of matches."""
    breakdown: dict[str, int] = {s.value: 0 for s in Severity}
    total = 0
    for match in matches:
        sev = match.severity
        weight = _SEVERITY_WEIGHTS.get(sev, 1)
        breakdown[sev.value] += weight
        total += weight
    return total, breakdown


def score_result(result: ScanResult) -> FileScore:
    """Compute a FileScore for a single ScanResult."""
    total, breakdown = _score_matches(result.matches)
    return FileScore(
        path=result.path,
        score=total,
        match_count=len(result.matches),
        breakdown=breakdown,
    )


def build_score_report(results: List[ScanResult]) -> ScoreReport:
    """Build a ScoreReport from a list of ScanResults."""
    return ScoreReport(file_scores=[score_result(r) for r in results])
