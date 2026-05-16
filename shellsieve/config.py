"""Configuration loader for shellsieve.

Supports reading options from a TOML config file (e.g. .shellsieve.toml)
or falling back to sensible defaults.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

_DEFAULT_CONFIG_NAMES = (".shellsieve.toml", "shellsieve.toml")


@dataclass
class Config:
    """Runtime configuration for a shellsieve scan."""

    # Minimum severity level to report (LOW, MEDIUM, HIGH)
    min_severity: str = "LOW"

    # Pattern IDs to ignore globally (supplements inline suppression)
    ignored_ids: List[str] = field(default_factory=list)

    # Treat any finding as a non-fatal warning (exit 0 even with issues)
    exit_zero: bool = False

    # Colour output in the terminal
    colour: bool = True


def _find_config_file(start: Path) -> Optional[Path]:
    """Walk upward from *start* looking for a config file."""
    for directory in (start, *start.parents):
        for name in _DEFAULT_CONFIG_NAMES:
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def load_config(search_dir: Optional[Path] = None) -> Config:
    """Load configuration, merging file values over defaults.

    Parameters
    ----------
    search_dir:
        Directory to begin searching for a config file.  Defaults to
        the current working directory.
    """
    config = Config()

    search_dir = search_dir or Path.cwd()
    config_path = _find_config_file(search_dir)

    if config_path is None:
        return config

    with config_path.open("rb") as fh:
        data = tomllib.load(fh)

    section = data.get("shellsieve", {})

    if "min_severity" in section:
        config.min_severity = str(section["min_severity"]).upper()

    if "ignored_ids" in section:
        config.ignored_ids = [str(i) for i in section["ignored_ids"]]

    if "exit_zero" in section:
        config.exit_zero = bool(section["exit_zero"])

    if "colour" in section:
        config.colour = bool(section["colour"])

    return config
