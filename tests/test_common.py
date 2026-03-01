"""
tests/test_common.py
Unit tests for common/logger.py and common/config_loader.py.
"""

import logging
import os
import textwrap
from pathlib import Path

import pytest
import yaml

from common.logger import get_logger, set_all_loggers_level
from common.config_loader import load_config, get_nested


# ---------------------------------------------------------------------------
# Logger tests
# ---------------------------------------------------------------------------

class TestGetLogger:
    def test_returns_logger_instance(self, tmp_path):
        logger = get_logger("test.module", log_dir=tmp_path)
        assert isinstance(logger, logging.Logger)

    def test_log_file_created(self, tmp_path):
        logger = get_logger("test.file_created", log_dir=tmp_path)
        logger.info("hello")
        log_files = list(tmp_path.glob("*.log"))
        assert len(log_files) == 1

    def test_no_duplicate_handlers(self, tmp_path):
        logger1 = get_logger("test.dedup", log_dir=tmp_path)
        logger2 = get_logger("test.dedup", log_dir=tmp_path)
        assert logger1 is logger2
        assert len(logger1.handlers) == len(logger2.handlers)

    def test_set_all_loggers_level(self, tmp_path):
        logger = get_logger("test.level_change", log_dir=tmp_path)
        set_all_loggers_level("DEBUG")
        assert logger.level == logging.DEBUG


# ---------------------------------------------------------------------------
# Config loader tests
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def _write_yaml(self, tmp_path: Path, content: str) -> Path:
        f = tmp_path / "config.yaml"
        f.write_text(textwrap.dedent(content))
        return f

    def test_loads_simple_yaml(self, tmp_path):
        f = self._write_yaml(tmp_path, """\
            backup:
              retention_days: 30
              destination: /mnt/backup
        """)
        cfg = load_config(f)
        assert cfg["backup"]["retention_days"] == 30

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_invalid_yaml_raises(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("key: [unclosed")
        with pytest.raises(yaml.YAMLError):
            load_config(f)

    def test_required_keys_pass(self, tmp_path):
        f = self._write_yaml(tmp_path, "host: localhost\nport: 8080\n")
        cfg = load_config(f, required_keys=["host", "port"])
        assert cfg["host"] == "localhost"

    def test_required_keys_missing_raises(self, tmp_path):
        f = self._write_yaml(tmp_path, "host: localhost\n")
        with pytest.raises(ValueError, match="missing required keys"):
            load_config(f, required_keys=["host", "port"])

    def test_env_var_interpolation(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_DB_PASS", "secret123")
        f = self._write_yaml(tmp_path, "db_password: ${TEST_DB_PASS}\n")
        cfg = load_config(f)
        assert cfg["db_password"] == "secret123"

    def test_env_var_default(self, tmp_path, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        f = self._write_yaml(tmp_path, "val: ${MISSING_VAR:-fallback}\n")
        cfg = load_config(f)
        assert cfg["val"] == "fallback"

    def test_env_var_missing_no_default_raises(self, tmp_path, monkeypatch):
        monkeypatch.delenv("NO_DEFAULT_VAR", raising=False)
        f = self._write_yaml(tmp_path, "val: ${NO_DEFAULT_VAR}\n")
        with pytest.raises(KeyError):
            load_config(f)

    def test_interpolation_disabled(self, tmp_path, monkeypatch):
        monkeypatch.delenv("SOME_VAR", raising=False)
        f = self._write_yaml(tmp_path, "val: ${SOME_VAR}\n")
        cfg = load_config(f, interpolate_env=False)
        assert cfg["val"] == "${SOME_VAR}"


class TestGetNested:
    def test_existing_path(self):
        cfg = {"a": {"b": {"c": 42}}}
        assert get_nested(cfg, "a", "b", "c") == 42

    def test_missing_key_returns_default(self):
        cfg = {"a": {}}
        assert get_nested(cfg, "a", "b", "c", default=99) == 99

    def test_none_default_when_missing(self):
        assert get_nested({}, "x") is None
