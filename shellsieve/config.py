"""Configuration loading for shellsieve."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]


@dataclass
class Config:
    """Resolved configuration used throughout shellsieve."""

    severity_threshold: str = "low"
    ignore_patterns: List[str] = field(default_factory=list)
    ignore_ids: List[str] = field(default_factory=list)
    exit_zero: bool = False
    output_format: str = "text"
    baseline_file: Optional[str] = None
    cache_dir: Optional[str] = None


def _find_config_file(start: Path | None = None) -> Optional[Path]:
    """Walk upward from *start* (default: cwd) looking for shellsieve.toml."""
    current = (start or Path.cwd()).resolve()
    for directory in [current, *current.parents]:
        candidate = directory / "shellsieve.toml"
        if candidate.is_file():
            return candidate
    return None


def load_config(path: Path | None = None) -> Config:
    """Load config from *path*, auto-discover if None, or return defaults."""
    config_path = path or _find_config_file()
    if config_path is None or not config_path.is_file():
        return Config()

    with open(config_path, "rb") as fh:
        data = tomllib.load(fh)

    tool_cfg = data.get("tool", {}).get("shellsieve", data)

    return Config(
        severity_threshold=tool_cfg.get("severity_threshold", "low"),
        ignore_patterns=tool_cfg.get("ignore_patterns", []),
        ignore_ids=tool_cfg.get("ignore_ids", []),
        exit_zero=tool_cfg.get("exit_zero", False),
        output_format=tool_cfg.get("output_format", "text"),
        baseline_file=tool_cfg.get("baseline_file"),
        cache_dir=tool_cfg.get("cache_dir"),
    )
