"""Analyzers for DNS, HTTP, SSL, and security checks.

With the modular registry system, analyzers auto-register themselves using
the @registry.register decorator. This module auto-imports all analyzer
modules to trigger their registration.
"""

import importlib
import pkgutil
from pathlib import Path

# Auto-import all analyzer modules to trigger @registry.register decorators
_analyzer_dir = Path(__file__).parent
for module_info in pkgutil.iter_modules([str(_analyzer_dir)]):
    if not module_info.name.startswith("_") and module_info.name != "protocol":
        importlib.import_module(f".{module_info.name}", package=__name__)

__all__ = []
