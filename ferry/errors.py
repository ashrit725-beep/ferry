"""Error types that carry a message safe to show to an operator."""

from __future__ import annotations

from typing import Any


class FerryError(Exception):
    """Base class. `message` is shown to users; never put secrets in it."""

    code = "ferry_error"

    def __init__(self, message: str, *, code: str | None = None, details: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        if code:
            self.code = code
        self.details = details or {}


class ConfigError(FerryError):
    code = "config_error"


class NotFound(FerryError):
    code = "not_found"


class Conflict(FerryError):
    code = "conflict"


class ValidationFailed(FerryError):
    code = "validation_failed"


class CryptoError(FerryError):
    code = "crypto_error"


class PermissionDenied(FerryError):
    code = "permission_denied"
