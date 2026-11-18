"""Errors of the backend database layer. Messages are written here, never copied from
the driver (which may quote SQL values), so they never contain a password, hash,
code, token or key."""


class RepositoryError(Exception):
    """Base class."""


class InvalidValue(RepositoryError, ValueError):
    """A value was refused before any database work (wrong role, plaintext where a hash
    is required, ...). Nothing was written."""


class DuplicateEmail(RepositoryError, ValueError):
    """Another account already uses this email address (compared ignoring case)."""


class NotFound(RepositoryError, LookupError):
    """The record does not exist."""


class BackendDatabaseUnavailable(RepositoryError):
    """The database could not be reached or the connection was lost.
    uncertain=True: lost while committing, so the change may or may not be saved."""

    def __init__(self, message, code=None, uncertain=False):
        self.code, self.uncertain = code, bool(uncertain)
        super().__init__(message)


class BackendDatabaseError(RepositoryError):
    """The database refused or failed one request (SQL error). Nothing was saved."""

    def __init__(self, message, code=None):
        self.code = code
        super().__init__(message)


class MigrationError(RepositoryError):
    """The migration state is unknown, inconsistent or unsafe: nothing more was run."""


class LastActiveAdmin(InvalidValue):
    """The change would leave no active admin (demoting or disabling the last one).
    Nothing was changed."""
