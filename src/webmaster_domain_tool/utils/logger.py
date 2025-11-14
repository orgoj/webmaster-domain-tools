"""Logging configuration for the application."""

import logging
import sys
from typing import Literal

VerbosityLevel = Literal["quiet", "normal", "verbose", "debug"]


def setup_logger(
    name: str = "webmaster_domain_tool",
    level: VerbosityLevel = "normal",
) -> logging.Logger:
    """
    Set up and configure logger.

    Args:
        name: Logger name
        level: Verbosity level (quiet, normal, verbose, debug)

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)

    # Remove existing handlers
    logger.handlers.clear()

    # Map verbosity levels to logging levels
    level_map = {
        "quiet": logging.ERROR,
        "normal": logging.WARNING,
        "verbose": logging.INFO,
        "debug": logging.DEBUG,
    }

    logger.setLevel(level_map[level])

    # Create console handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level_map[level])

    # Create formatter
    if level == "debug":
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
