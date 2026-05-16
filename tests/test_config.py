"""Tests for shellsieve.config."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from shellsieve.config import Config, load_config, _find_config_file


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_toml(tmp_path: Path, content: str) -> Path:
    cfg = tmp_path / ".shellsieve.toml"
    cfg.write_text(textwrap.dedent(content))
    return cfg


# ---------------------------------------------------------------------------
# Config dataclass defaults
# ---------------------------------------------------------------------------

def test_default_config_values():
    cfg = Config()
    assert cfg.min_severity == "LOW"
    assert cfg.ignored_ids == []
    assert cfg.exit_zero is False
    assert cfg.colour is True


# ---------------------------------------------------------------------------
# _find_config_file
# ---------------------------------------------------------------------------

def test_find_config_file_in_same_dir(tmp_path):
    cfg = tmp_path / ".shellsieve.toml"
    cfg.write_text("")
    assert _find_config_file(tmp_path) == cfg


def test_find_config_file_walks_upward(tmp_path):
    cfg = tmp_path / ".shellsieve.toml"
    cfg.write_text("")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert _find_config_file(nested) == cfg


def test_find_config_file_returns_none_when_absent(tmp_path):
    assert _find_config_file(tmp_path) is None


# ---------------------------------------------------------------------------
# load_config — no file present
# ---------------------------------------------------------------------------

def test_load_config_no_file_returns_defaults(tmp_path):
    cfg = load_config(search_dir=tmp_path)
    assert isinstance(cfg, Config)
    assert cfg.min_severity == "LOW"


# ---------------------------------------------------------------------------
# load_config — with file
# ---------------------------------------------------------------------------

def test_load_config_reads_min_severity(tmp_path):
    _write_toml(tmp_path, """
        [shellsieve]
        min_severity = "HIGH"
    """)
    cfg = load_config(search_dir=tmp_path)
    assert cfg.min_severity == "HIGH"


def test_load_config_reads_ignored_ids(tmp_path):
    _write_toml(tmp_path, """
        [shellsieve]
        ignored_ids = ["SS001", "SS002"]
    """)
    cfg = load_config(search_dir=tmp_path)
    assert cfg.ignored_ids == ["SS001", "SS002"]


def test_load_config_reads_exit_zero(tmp_path):
    _write_toml(tmp_path, """
        [shellsieve]
        exit_zero = true
    """)
    cfg = load_config(search_dir=tmp_path)
    assert cfg.exit_zero is True


def test_load_config_reads_colour(tmp_path):
    _write_toml(tmp_path, """
        [shellsieve]
        colour = false
    """)
    cfg = load_config(search_dir=tmp_path)
    assert cfg.colour is False


def test_load_config_empty_section_uses_defaults(tmp_path):
    _write_toml(tmp_path, "[shellsieve]\n")
    cfg = load_config(search_dir=tmp_path)
    assert cfg.min_severity == "LOW"
    assert cfg.ignored_ids == []
