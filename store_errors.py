"""Errors raised by both stores (db.py and db_fake.py), so the screens can tell them apart.

They are ValueErrors, so code that only knows ValueError still shows a clear message.
They carry only non-sensitive device details: never a username, password or key.
"""


class DeletedDeviceExists(ValueError):
    """The IP belongs to a soft-deleted device. Nothing was saved and the deleted record
    was not touched. .device = {'id', 'name', 'ip', 'type', 'has_login'}."""

    def __init__(self, device):
        self.device = {'id': device['id'], 'name': device['name'], 'ip': device['ip'],
                       'type': device.get('type', 'unknown'),
                       'has_login': bool(device.get('has_login'))}
        super().__init__(f"IP {self.device['ip']} belongs to the deleted device "
                         f"{self.device['name']} ({self.device['type']}). It was not restored "
                         f"and nothing was saved.")


class DeviceNotDeleted(ValueError):
    """restore_device was asked to restore a device that is not deleted (for example it was
    already restored). Nothing was changed."""


# ---------------------------------------------------------------- database problems
# These are NOT ValueErrors: they are not about the data the user typed, so code that
# handles validation errors never mistakes an outage for one. Their messages are written
# here, never copied from the driver, so they can never contain a password, an encrypted
# login, the encryption key or the SQL values that were being sent.

class DatabaseUnavailable(Exception):
    """The database could not be reached, or the connection was lost.

    uncertain=False (the usual case): the request did not complete, so nothing of it was
    saved (an unfinished transaction is rolled back by the server).
    uncertain=True: the connection was lost while the server was committing a change, so
    the client cannot know whether it was saved. Check again once the database is back."""

    def __init__(self, message, code=None, uncertain=False):
        self.code, self.uncertain = code, bool(uncertain)
        super().__init__(message)


class DatabaseError(Exception):
    """The database is reachable but refused or failed one request (a SQL error).
    Nothing of that request was saved."""

    def __init__(self, message, code=None):
        self.code = code
        super().__init__(message)


DATABASE_ERRORS = (DatabaseUnavailable, DatabaseError)


def outcome_text(err, nothing='Nothing was saved.'):
    """What happened to a write that failed with err, said honestly: 'nothing' for every
    failure except a connection lost during the commit, where the result is unknown."""
    if isinstance(err, DatabaseUnavailable) and err.uncertain:
        return ('The connection was lost while the change was being committed, so it may or '
                'may not have been saved. Check once the database is available again.')
    return nothing


# ---------------------------------------------------------------- device names
class DuplicateDeviceName(ValueError):
    """Another ACTIVE device already uses this name (compared ignoring capital letters).
    Deleted devices never count. Nothing was saved or changed.
    .existing = {'id', 'name'} of that device (never its login)."""

    def __init__(self, name, existing):
        self.name = name
        self.existing = {'id': existing['id'], 'name': existing['name']}
        super().__init__(f"The name {name} is already used by the device "
                         f"{self.existing['name']} (ID {self.existing['id']}). Device names "
                         f"must be unique; capital letters do not make a name different.")
