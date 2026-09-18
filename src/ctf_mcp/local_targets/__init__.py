"""Trusted host-side local target adapters.

This package is imported by ``scripts/control.py`` only.  It intentionally does
not expose an MCP execution surface.
"""

from .base import LocalTargetError, load_adapter

__all__ = ["LocalTargetError", "load_adapter"]
