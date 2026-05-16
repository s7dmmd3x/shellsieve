"""Simple file-based scan cache keyed on file path + mtime + content hash."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Optional

_DEFAULT_CACHE_FILE = Path(".shellsieve_cache.json")


def _file_digest(path: Path) -> str:
    """Return a hex digest of the file's contents."""
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def _cache_key(path: Path) -> dict:
    stat = path.stat()
    return {
        "mtime": stat.st_mtime,
        "size": stat.st_size,
        "digest": _file_digest(path),
    }


def load_cache(cache_file: Path = _DEFAULT_CACHE_FILE) -> dict:
    """Load the on-disk cache; return an empty dict if absent or corrupt."""
    if not cache_file.exists():
        return {}
    try:
        return json.loads(cache_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def save_cache(cache: dict, cache_file: Path = _DEFAULT_CACHE_FILE) -> None:
    """Persist the cache dict to disk."""
    cache_file.write_text(json.dumps(cache, indent=2), encoding="utf-8")


def is_cached(path: Path, cache: dict) -> bool:
    """Return True when *path* is present in the cache and unchanged."""
    key = str(path.resolve())
    if key not in cache:
        return False
    stored = cache[key]
    try:
        current = _cache_key(path)
    except OSError:
        return False
    return (
        stored.get("mtime") == current["mtime"]
        and stored.get("size") == current["size"]
        and stored.get("digest") == current["digest"]
    )


def mark_cached(path: Path, cache: dict) -> None:
    """Record *path* in *cache* using its current mtime/size/digest."""
    key = str(path.resolve())
    cache[key] = _cache_key(path)


def invalidate(path: Path, cache: dict) -> None:
    """Remove *path* from *cache* if present."""
    cache.pop(str(path.resolve()), None)
