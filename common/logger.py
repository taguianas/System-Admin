"""
common/logger.py
Unified logging module used by all scripts in the project.

Features:
- File logging with automatic rotation (10 MB per file, 5 backups)
- Console logging with colored output (if colorama is available)
- Per-module named loggers
- Configurable log level via environment variable LOG_LEVEL
"""

import logging
import logging.handlers
import os
import sys
from pathlib import Path


# Default log directory — scripts can override via get_logger(log_dir=...)
DEFAULT_LOG_DIR = Path(__file__).resolve().parent.parent / "logs"

# Max size per log file before rotation (bytes)
LOG_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
LOG_BACKUP_COUNT = 5

# Log format
LOG_FORMAT = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# Try to import colorama for colored console output (optional dependency)
try:
    from colorama import Fore, Style, init as colorama_init
    colorama_init(autoreset=True)
    _COLORS = {
        "DEBUG": Fore.CYAN,
        "INFO": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA + Style.BRIGHT,
    }
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False


class ColoredFormatter(logging.Formatter):
    """Console formatter that colorizes the level name."""

    def format(self, record: logging.LogRecord) -> str:
        if _HAS_COLOR:
            color = _COLORS.get(record.levelname, "")
            record.levelname = f"{color}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)


def get_logger(
    name: str,
    log_dir: Path | str | None = None,
    level: str | None = None,
    log_to_file: bool = True,
    log_to_console: bool = True,
) -> logging.Logger:
    """
    Return a configured logger.

    Parameters
    ----------
    name:
        Logger name — use __name__ from the calling module, e.g.
        ``logger = get_logger(__name__)``
    log_dir:
        Directory where log files are stored.  Defaults to <project-root>/logs/.
    level:
        Log level string ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL').
        Falls back to the LOG_LEVEL environment variable, then 'INFO'.
    log_to_file:
        Whether to write logs to a rotating file.
    log_to_console:
        Whether to print logs to stderr.

    Returns
    -------
    logging.Logger
    """
    logger = logging.getLogger(name)

    # Avoid adding duplicate handlers if this logger was already configured
    if logger.handlers:
        return logger

    # Resolve level
    resolved_level = level or os.environ.get("LOG_LEVEL", "INFO")
    numeric_level = getattr(logging, resolved_level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # File handler
    if log_to_file:
        resolved_dir = Path(log_dir) if log_dir else DEFAULT_LOG_DIR
        resolved_dir.mkdir(parents=True, exist_ok=True)
        log_file = resolved_dir / f"{name.replace('.', '_')}.log"

        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=LOG_MAX_BYTES,
            backupCount=LOG_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
        logger.addHandler(file_handler)

    # Console handler
    if log_to_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(
            ColoredFormatter(LOG_FORMAT, datefmt=DATE_FORMAT)
        )
        logger.addHandler(console_handler)

    # Prevent log records from propagating to the root logger
    logger.propagate = False

    return logger


def set_all_loggers_level(level: str) -> None:
    """
    Retroactively set the level on every logger created by get_logger().

    Useful when a CLI flag like --debug is parsed after loggers are initialized.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    for logger_name, logger in logging.Logger.manager.loggerDict.items():
        if isinstance(logger, logging.Logger):
            logger.setLevel(numeric_level)
            for handler in logger.handlers:
                handler.setLevel(numeric_level)
