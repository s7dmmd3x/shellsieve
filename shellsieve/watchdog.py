"""File-system watcher that re-scans shell scripts on change."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional


@dataclass
class WatchedFile:
    path: Path
    last_mtime: float = 0.0
    last_size: int = 0

    def has_changed(self) -> bool:
        """Return True when the file's mtime or size differs from last snapshot."""
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return False
        changed = st.st_mtime != self.last_mtime or st.st_size != self.last_size
        if changed:
            self.last_mtime = st.st_mtime
            self.last_size = st.st_size
        return changed


@dataclass
class WatchSession:
    """Tracks a collection of paths and fires a callback when any changes."""

    callback: Callable[[List[Path]], None]
    interval: float = 1.0
    _watched: Dict[Path, WatchedFile] = field(default_factory=dict, init=False)
    _running: bool = field(default=False, init=False)

    def add_paths(self, paths: Iterable[Path]) -> None:
        for p in paths:
            if p not in self._watched:
                wf = WatchedFile(path=p)
                # Initialise snapshot so first poll does not always fire.
                try:
                    st = p.stat()
                    wf.last_mtime = st.st_mtime
                    wf.last_size = st.st_size
                except FileNotFoundError:
                    pass
                self._watched[p] = wf

    def poll_once(self) -> List[Path]:
        """Check all watched files; return list of changed paths."""
        changed: List[Path] = []
        for wf in self._watched.values():
            if wf.has_changed():
                changed.append(wf.path)
        return changed

    def start(self, max_cycles: Optional[int] = None) -> None:
        """Block and poll until *max_cycles* iterations (None = forever)."""
        self._running = True
        cycles = 0
        try:
            while self._running:
                changed = self.poll_once()
                if changed:
                    self.callback(changed)
                cycles += 1
                if max_cycles is not None and cycles >= max_cycles:
                    break
                time.sleep(self.interval)
        finally:
            self._running = False

    def stop(self) -> None:
        self._running = False
