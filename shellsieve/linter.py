"""Lint-mode runner: aggregate scan results into a structured lint report."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from shellsieve.scanner import Match, ScanResult, scan_file
from shellsieve.suppression import filter_suppressed
from shellsieve.config import Config


@dataclass
class FileLintResult:
    path: Path
    matches: List[Match]
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return not self.matches and self.error is None

    @property
    def error_count(self) -> int:
        from shellsieve.patterns import Severity
        return sum(1 for m in self.matches if m.severity == Severity.ERROR)

    @property
    def warning_count(self) -> int:
        from shellsieve.patterns import Severity
        return sum(1 for m in self.matches if m.severity == Severity.WARNING)


@dataclass
class LintReport:
    results: List[FileLintResult] = field(default_factory=list)

    @property
    def total_errors(self) -> int:
        return sum(r.error_count for r in self.results)

    @property
    def total_warnings(self) -> int:
        return sum(r.warning_count for r in self.results)

    @property
    def failed_files(self) -> List[FileLintResult]:
        return [r for r in self.results if not r.ok]

    @property
    def passed_files(self) -> List[FileLintResult]:
        return [r for r in self.results if r.ok]

    def as_dict(self) -> Dict:
        return {
            "total_files": len(self.results),
            "failed_files": len(self.failed_files),
            "total_errors": self.total_errors,
            "total_warnings": self.total_warnings,
        }


def lint_files(paths: List[Path], config: Optional[Config] = None) -> LintReport:
    """Scan each path and return a consolidated LintReport."""
    from shellsieve.patterns import get_patterns_by_severity, Severity
    from shellsieve.scanner import scan_lines
    from shellsieve.patterns import PATTERNS  # type: ignore

    cfg = config or Config()
    report = LintReport()

    for path in paths:
        try:
            result: ScanResult = scan_file(path)
            filtered = filter_suppressed(result.matches)
            if cfg.min_severity:
                order = [Severity.INFO, Severity.WARNING, Severity.ERROR]
                min_idx = order.index(cfg.min_severity)
                filtered = [m for m in filtered if order.index(m.severity) >= min_idx]
            report.results.append(FileLintResult(path=path, matches=filtered))
        except OSError as exc:
            report.results.append(FileLintResult(path=path, matches=[], error=str(exc)))

    return report
