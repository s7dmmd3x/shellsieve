"""Track scan results over time and report trends across runs."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Dict, Optional


@dataclass
class TrendEntry:
    timestamp: float
    total_issues: int
    error_count: int
    warning_count: int
    file_count: int
    scanned_files: int

    def as_dict(self) -> Dict:
        return {
            "timestamp": self.timestamp,
            "total_issues": self.total_issues,
            "error_count": self.error_count,
            "warning_count": self.warning_count,
            "file_count": self.file_count,
            "scanned_files": self.scanned_files,
        }

    @staticmethod
    def from_dict(d: Dict) -> "TrendEntry":
        return TrendEntry(
            timestamp=float(d["timestamp"]),
            total_issues=int(d["total_issues"]),
            error_count=int(d["error_count"]),
            warning_count=int(d["warning_count"]),
            file_count=int(d["file_count"]),
            scanned_files=int(d["scanned_files"]),
        )


@dataclass
class TrendReport:
    entries: List[TrendEntry] = field(default_factory=list)

    def latest(self) -> Optional[TrendEntry]:
        return self.entries[-1] if self.entries else None

    def delta(self) -> Optional[Dict[str, int]]:
        """Return change in counts between the last two entries."""
        if len(self.entries) < 2:
            return None
        prev, curr = self.entries[-2], self.entries[-1]
        return {
            "total_issues": curr.total_issues - prev.total_issues,
            "error_count": curr.error_count - prev.error_count,
            "warning_count": curr.warning_count - prev.warning_count,
        }


def load_trend(path: Path) -> TrendReport:
    if not path.exists():
        return TrendReport()
    data = json.loads(path.read_text())
    entries = [TrendEntry.from_dict(e) for e in data.get("entries", [])]
    return TrendReport(entries=entries)


def save_trend(report: TrendReport, path: Path) -> None:
    path.write_text(json.dumps({"entries": [e.as_dict() for e in report.entries]}, indent=2))


def record_entry(report: TrendReport, entry: TrendEntry, max_entries: int = 100) -> TrendReport:
    entries = list(report.entries) + [entry]
    return TrendReport(entries=entries[-max_entries:])


def make_entry(stats_dict: Dict) -> TrendEntry:
    """Build a TrendEntry from a ScanStats.as_dict() payload."""
    return TrendEntry(
        timestamp=time.time(),
        total_issues=stats_dict.get("total_issues", 0),
        error_count=stats_dict.get("error_count", 0),
        warning_count=stats_dict.get("warning_count", 0),
        file_count=stats_dict.get("file_count", 0),
        scanned_files=stats_dict.get("scanned_files", 0),
    )
