"""Error types that carry a message safe to show to an operator."""

from __future__ import annotations

import sqlite3
import traceback
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


def operator_detail(exc: BaseException) -> str:
    """What the server log may say about an unexpected exception: its class, plus
    the text of the kinds whose message is fixed by the system and never holds
    request data (SQLite errors, and OS errors as errno and strerror, without
    the file name). Disk full, database locked, read-only database and I/O error
    are then told apart in the log."""
    name = type(exc).__name__
    if isinstance(exc, sqlite3.Error):
        code = getattr(exc, "sqlite_errorname", None)
        return f"{name}: {exc}" + (f" ({code})" if code else "")
    if isinstance(exc, OSError) and (exc.errno is not None or exc.strerror):
        return f"{name}: [Errno {exc.errno}] {exc.strerror}"
    return name


def operator_traceback(exc: BaseException) -> str:
    """The stack of `exc` as frames and source lines only. Unlike exc_info=True,
    the exception's own text (which can echo request data) is left out."""
    return "".join(traceback.format_tb(exc.__traceback__)).rstrip()
