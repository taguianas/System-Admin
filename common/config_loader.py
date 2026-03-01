"""
common/config_loader.py
YAML configuration loader used by all scripts.

Features:
- Load a YAML file and return a plain dict
- Optional schema validation via a required-keys list
- Environment variable interpolation: ${VAR} or ${VAR:-default}
- Raises clear errors on missing files or bad syntax
"""

import os
import re
from pathlib import Path
from typing import Any

import yaml

from common.logger import get_logger

logger = get_logger(__name__)

# Matches ${VAR} or ${VAR:-default_value}
_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _interpolate_env(value: str) -> str:
    """Replace ${VAR} and ${VAR:-default} patterns with environment values."""
    def replacer(match: re.Match) -> str:
        var_name, default = match.group(1), match.group(2)
        env_val = os.environ.get(var_name)
        if env_val is not None:
            return env_val
        if default is not None:
            return default
        raise KeyError(
            f"Environment variable '{var_name}' is not set and has no default."
        )

    return _ENV_VAR_RE.sub(replacer, value)


def _walk_and_interpolate(obj: Any) -> Any:
    """Recursively interpolate env vars in all string values of a dict/list."""
    if isinstance(obj, dict):
        return {k: _walk_and_interpolate(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_walk_and_interpolate(item) for item in obj]
    if isinstance(obj, str):
        return _interpolate_env(obj)
    return obj


def load_config(
    path: str | Path,
    required_keys: list[str] | None = None,
    interpolate_env: bool = True,
) -> dict[str, Any]:
    """
    Load a YAML configuration file.

    Parameters
    ----------
    path:
        Path to the YAML file.
    required_keys:
        Top-level keys that must be present.  Raises ValueError if any are missing.
    interpolate_env:
        If True (default), replace ``${VAR}`` / ``${VAR:-default}`` placeholders
        with the corresponding environment variables.

    Returns
    -------
    dict
        Parsed configuration as a Python dict.

    Raises
    ------
    FileNotFoundError
        If the config file does not exist.
    yaml.YAMLError
        If the file contains invalid YAML.
    ValueError
        If required keys are missing from the config.
    KeyError
        If an env-var placeholder references an unset variable with no default.
    """
    config_path = Path(path)

    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    logger.debug("Loading config: %s", config_path)

    with config_path.open("r", encoding="utf-8") as fh:
        try:
            raw = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            raise yaml.YAMLError(f"Invalid YAML in {config_path}: {exc}") from exc

    if raw is None:
        raw = {}

    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file must contain a YAML mapping at the top level, "
            f"got {type(raw).__name__}: {config_path}"
        )

    if interpolate_env:
        raw = _walk_and_interpolate(raw)

    if required_keys:
        missing = [k for k in required_keys if k not in raw]
        if missing:
            raise ValueError(
                f"Config '{config_path}' is missing required keys: {missing}"
            )

    logger.debug("Config loaded successfully from %s", config_path)
    return raw


def get_nested(config: dict, *keys: str, default: Any = None) -> Any:
    """
    Safely retrieve a nested value from a config dict.

    Example
    -------
    >>> get_nested(cfg, "backup", "retention_days", default=30)
    """
    current = config
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, None)
        if current is None:
            return default
    return current
