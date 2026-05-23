"""Lazy imports for optional third-party dependencies."""

from __future__ import annotations

from importlib import import_module
from types import ModuleType

from .errors import DependencyMissingError


def require_module(name: str, package: str | None = None) -> ModuleType:
    try:
        return import_module(name)
    except ImportError as exc:
        install_name = package or name
        raise DependencyMissingError(
            f"Missing dependency '{name}'. Install it with: pip install {install_name}"
        ) from exc


def require_lief() -> ModuleType:
    return require_module("lief")


def require_keystone() -> ModuleType:
    return require_module("keystone", "keystone-engine")


def require_capstone() -> ModuleType:
    return require_module("capstone")
