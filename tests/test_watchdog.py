"""Tests for shellsieve.watchdog."""

from __future__ import annotations

import time
from pathlib import Path
from typing import List

import pytest

from shellsieve.watchdog import WatchSession, WatchedFile


# ---------------------------------------------------------------------------
# WatchedFile
# ---------------------------------------------------------------------------

def test_watched_file_detects_change(tmp_path: Path) -> None:
    f = tmp_path / "script.sh"
    f.write_text("echo hello")
    wf = WatchedFile(path=f)
    # Initialise snapshot manually (as WatchSession does).
    st = f.stat()
    wf.last_mtime = st.st_mtime
    wf.last_size = st.st_size

    # No change yet.
    assert not wf.has_changed()

    # Modify the file — use a future mtime to avoid sub-second resolution issues.
    f.write_text("echo world")
    future = time.time() + 10
    import os
    os.utime(f, (future, future))

    assert wf.has_changed()


def test_watched_file_missing_returns_false(tmp_path: Path) -> None:
    f = tmp_path / "ghost.sh"
    wf = WatchedFile(path=f)
    assert not wf.has_changed()


# ---------------------------------------------------------------------------
# WatchSession.add_paths
# ---------------------------------------------------------------------------

def test_add_paths_registers_files(tmp_path: Path) -> None:
    f = tmp_path / "a.sh"
    f.write_text("true")
    session = WatchSession(callback=lambda _: None)
    session.add_paths([f])
    assert f in session._watched


def test_add_paths_deduplicates(tmp_path: Path) -> None:
    f = tmp_path / "a.sh"
    f.write_text("true")
    session = WatchSession(callback=lambda _: None)
    session.add_paths([f, f])
    assert len(session._watched) == 1


# ---------------------------------------------------------------------------
# WatchSession.poll_once
# ---------------------------------------------------------------------------

def test_poll_once_empty_on_no_change(tmp_path: Path) -> None:
    f = tmp_path / "a.sh"
    f.write_text("true")
    session = WatchSession(callback=lambda _: None)
    session.add_paths([f])
    assert session.poll_once() == []


def test_poll_once_returns_changed_path(tmp_path: Path) -> None:
    f = tmp_path / "a.sh"
    f.write_text("true")
    session = WatchSession(callback=lambda _: None)
    session.add_paths([f])

    # Force a change.
    f.write_text("false")
    import os, time
    os.utime(f, (time.time() + 5, time.time() + 5))

    changed = session.poll_once()
    assert f in changed


# ---------------------------------------------------------------------------
# WatchSession.start / stop with max_cycles
# ---------------------------------------------------------------------------

def test_start_fires_callback_on_change(tmp_path: Path) -> None:
    f = tmp_path / "b.sh"
    f.write_text("echo 1")

    fired: List[Path] = []

    def cb(paths: List[Path]) -> None:
        fired.extend(paths)

    session = WatchSession(callback=cb, interval=0)
    session.add_paths([f])

    # Mutate before starting so the first poll picks it up.
    import os, time
    f.write_text("echo 2")
    os.utime(f, (time.time() + 5, time.time() + 5))

    session.start(max_cycles=1)
    assert f in fired


def test_stop_halts_session(tmp_path: Path) -> None:
    session = WatchSession(callback=lambda _: None, interval=0)
    session.start(max_cycles=0)
    assert not session._running
