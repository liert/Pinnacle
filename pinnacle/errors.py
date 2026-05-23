"""Project-specific exceptions."""


class PinnacleError(Exception):
    """Base error for user-facing failures."""


class DependencyMissingError(PinnacleError):
    """Raised when an optional runtime dependency is required but unavailable."""


class UnsupportedElfError(PinnacleError):
    """Raised when the target ELF is outside the supported MVP scope."""


class SymbolResolutionError(PinnacleError):
    """Raised when a function symbol cannot be resolved to a callable address."""


class PatchPlanningError(PinnacleError):
    """Raised when a patch cannot be safely planned."""
