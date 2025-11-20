"""Renderers for analyzer output.

This package provides renderer implementations for different output formats.
All renderers implement the BaseRenderer protocol and are completely decoupled
from analyzer implementations.
"""

from .base import BaseRenderer
from .cli_renderer import CLIRenderer
from .json_renderer import JSONRenderer

__all__ = ["BaseRenderer", "CLIRenderer", "JSONRenderer"]
