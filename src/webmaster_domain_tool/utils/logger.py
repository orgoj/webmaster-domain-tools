"""Logging configuration for the application."""

import logging
import sys

from ..analyzers.protocol import VerbosityLevel


def setup_logger(
    name: str = "webmaster_domain_tool",
    level: VerbosityLevel = VerbosityLevel.NORMAL,
) -> logging.Logger:
    """
    Set up and configure logger.

    Args:
        name: Logger name
        level: Verbosity level enum

    Returns:
        Configured logger
    """
    logger = logging.getLogger(name)

    # Remove existing handlers
    logger.handlers.clear()

    # Map verbosity levels to logging levels
    level_map = {
        VerbosityLevel.QUIET: logging.ERROR,
        VerbosityLevel.NORMAL: logging.WARNING,
        VerbosityLevel.VERBOSE: logging.INFO,
        VerbosityLevel.DEBUG: logging.DEBUG,
    }

    logger.setLevel(level_map[level])

    # Create console handler
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level_map[level])

    # Create formatter
    if level == VerbosityLevel.DEBUG:
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    else:
        formatter = logging.Formatter("%(levelname)s: %(message)s")

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger
