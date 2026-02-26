"""
Quantum Protocol v3 — Plugin Architecture

Supports custom rule extensions and analyzer plugins.
Plugins are Python modules placed in this directory with:
  - A `register()` function that returns a list of PatternRule objects
  - Optional `analyze(content, filepath, language)` function for deep analysis
"""

from __future__ import annotations

import importlib
import logging
from pathlib import Path
from typing import Any

from quantum_protocol.rules.patterns import PatternRule

logger = logging.getLogger("quantum_protocol.plugins")

_registered_plugins: list[dict[str, Any]] = []


def load_plugins(plugin_dir: str | Path | None = None) -> list[PatternRule]:
    """
    Discover and load plugin modules from a directory.

    Each plugin module should expose:
      - register() -> list[PatternRule]
      - (optional) analyze(content: str, filepath: str, language: str) -> list[dict]
    """
    extra_rules: list[PatternRule] = []

    if plugin_dir is None:
        plugin_dir = Path(__file__).parent

    plugin_path = Path(plugin_dir)
    if not plugin_path.exists():
        return extra_rules

    for py_file in plugin_path.glob("plugin_*.py"):
        module_name = py_file.stem
        try:
            spec = importlib.util.spec_from_file_location(module_name, py_file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, "register"):
                    rules = module.register()
                    extra_rules.extend(rules)
                    logger.info("Loaded plugin '%s' with %d rules.", module_name, len(rules))

                plugin_entry = {"name": module_name, "module": module}
                if hasattr(module, "analyze"):
                    plugin_entry["analyzer"] = module.analyze

                _registered_plugins.append(plugin_entry)

        except Exception as e:
            logger.error("Failed to load plugin '%s': %s", module_name, e)

    return extra_rules


def get_plugin_analyzers() -> list:
    """Return all registered plugin analyzer functions."""
    return [p["analyzer"] for p in _registered_plugins if "analyzer" in p]
