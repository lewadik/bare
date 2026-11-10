"""Error types shared by client and server.

Every error carries a stable ``code`` (machine readable, part of the HTTP API)
and an HTTP ``status`` used by the daemon when the error escapes a handler.
"""

from __future__ import annotations


class HavenError(Exception):
    """Base class for all Haven errors."""

    code = "internal"
    status = 500

    def __init__(self, message: str, *, detail: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.detail = detail

    def as_dict(self) -> dict:
        out = {"code": self.code, "message": self.message}
        if self.detail:
            out["detail"] = self.detail
        return out


class ConfigError(HavenError):
    code = "config_error"
    status = 400


class UsageError(HavenError):
    code = "usage_error"
    status = 400


class AuthError(HavenError):
    code = "unauthorized"
    status = 401


class ForbiddenError(HavenError):
    code = "forbidden"
    status = 403


class NotFoundError(HavenError):
    code = "not_found"
    status = 404


class ConflictError(HavenError):
    code = "conflict"
    status = 409


class IntegrityError(HavenError):
    """Data on disk or on the wire does not match its recorded checksum."""

    code = "integrity_error"
    status = 422


class ProtocolError(HavenError):
    code = "protocol_error"
    status = 502


class RepositoryError(HavenError):
    """The repository is in an unexpected state (locked, corrupt, wrong layout)."""

    code = "repository_error"
    status = 500


class ObjectMissing(IntegrityError):
    """A chunk referenced by a snapshot is not present in the repository."""

    code = "object_missing"
    status = 422


class BusyError(HavenError):
    code = "busy"
    status = 503


class TooLargeError(HavenError):
    code = "payload_too_large"
    status = 413


_ERROR_TYPES: dict[str, type[HavenError]] = {}


def _register(cls: type[HavenError]) -> type[HavenError]:
    _ERROR_TYPES[cls.code] = cls
    return cls


for _cls in (
    ConfigError,
    UsageError,
    AuthError,
    ForbiddenError,
    NotFoundError,
    ConflictError,
    IntegrityError,
    ObjectMissing,
    ProtocolError,
    RepositoryError,
    BusyError,
    TooLargeError,
):
    _register(_cls)


class ErrorFactory:
    """Maps a machine-readable error code from the API back to a local class."""

    @staticmethod
    def get(code: str, default: type[HavenError] = HavenError) -> type[HavenError]:
        return _ERROR_TYPES.get(code, default)
