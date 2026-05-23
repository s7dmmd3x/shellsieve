"""CLI helper that wires the watchdog to the scanner and reporter."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

from shellsieve.config import load_config
from shellsieve.ignorer import build_ignore_patterns, filter_paths
from shellsieve.reporter import print_results
from shellsieve.scanner import scan_file
from shellsieve.watchdog import WatchSession


def _resolve_targets(raw: List[str]) -> List[Path]:
    """Expand directories to .sh/.bash/.zsh files; keep plain files as-is."""
    targets: List[Path] = []
    for item in raw:
        p = Path(item)
        if p.is_dir():
            for ext in ("*.sh", "*.bash", "*.zsh"):
                targets.extend(p.rglob(ext))
        elif p.exists():
            targets.append(p)
    return targets


def watch(
    paths: List[str],
    interval: float = 1.0,
    config_path: Optional[str] = None,
    max_cycles: Optional[int] = None,
) -> None:
    """Watch *paths* for changes and re-scan on modification."""
    cfg = load_config(Path(config_path) if config_path else None)
    ignore_pats = build_ignore_patterns(cfg.ignore_patterns)

    targets = _resolve_targets(paths)
    targets = filter_paths(targets, ignore_pats)

    if not targets:
        print("shellsieve watch: no files to watch.", file=sys.stderr)
        return

    print(f"Watching {len(targets)} file(s) — press Ctrl+C to stop.")

    def on_change(changed: List[Path]) -> None:
        for p in changed:
            print(f"\n[changed] {p}")
            result = scan_file(p)
            print_results(result)

    session = WatchSession(callback=on_change, interval=interval)
    session.add_paths(targets)
    try:
        session.start(max_cycles=max_cycles)
    except KeyboardInterrupt:
        print("\nWatch session ended.")
