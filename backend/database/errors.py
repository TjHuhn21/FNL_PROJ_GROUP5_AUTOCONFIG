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


class ResendTooSoon(RepositoryError):
    """A new code was requested within the resend cooldown. Nothing was created.
    retry_after_seconds: whole seconds until another code may be requested."""

    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = int(retry_after_seconds)
        super().__init__(f'A code was sent recently. Wait {self.retry_after_seconds} seconds '
                         f'before requesting another one.')


class EmailNotVerified(InvalidValue):
    """The account's email address has not been verified, so it cannot be (or become)
    active or await approval. Nothing was changed."""


class AdminExists(RepositoryError):
    """The first-administrator setup was refused: an active admin already exists."""


class SetupBusy(RepositoryError):
    """Another first-administrator setup holds the database lock right now."""


class LastActiveAdmin(InvalidValue):
    """The change would leave no active admin (demoting or disabling the last one).
    Nothing was changed."""


# ---------------------------------------------------------------- shared application data
# Raised by AppRepository and InMemoryAppRepository alike. They carry only non-sensitive
# device details (id, name, ip, type, has_login): never a username, password, token or key.
class DuplicateDeviceName(InvalidValue):
    """Another ACTIVE device already uses this name (compared ignoring capital letters).
    Deleted devices never count. Nothing was changed. .existing = {'id', 'name'}."""

    def __init__(self, name, existing=None):
        self.name = name
        existing = existing or {'id': None, 'name': None}
        self.existing = {'id': existing['id'], 'name': existing['name']}
        who = (f"the device {self.existing['name']} (ID {self.existing['id']})"
               if self.existing['id'] is not None else 'another device')
        super().__init__(f"The name {name} is already used by {who}. Device names must be "
                         f"unique; capital letters do not make a name different.")


class DuplicateDeviceIp(InvalidValue):
    """Another ACTIVE device already has this IP address. Nothing was changed.
    .existing = {'id', 'name'} (None values when only the database's unique index saw it)."""

    def __init__(self, ip, existing=None):
        self.ip = ip
        existing = existing or {'id': None, 'name': None}
        self.existing = {'id': existing['id'], 'name': existing['name']}
        who = (f"the device {self.existing['name']} (ID {self.existing['id']})"
               if self.existing['id'] is not None else 'another device')
        super().__init__(f"The IP address {ip} is already used by {who}. Nothing was changed.")


class DeletedDeviceExists(InvalidValue):
    """The IP belongs to a soft-deleted device. Nothing was saved and the deleted record was
    not touched (only restore_device brings it back).
    .device = {'id', 'name', 'ip', 'type', 'has_login'}."""

    def __init__(self, device):
        self.device = {'id': device['id'], 'name': device['name'], 'ip': device['ip'],
                       'type': device.get('type', 'unknown'),
                       'has_login': bool(device.get('has_login'))}
        super().__init__(f"IP {self.device['ip']} belongs to the deleted device "
                         f"{self.device['name']} ({self.device['type']}). It was not restored "
                         f"and nothing was saved.")


class DeviceNotDeleted(InvalidValue):
    """restore_device was asked to restore a device that is not deleted. Nothing changed."""


class VersionConflict(RepositoryError):
    """Optimistic locking: the record was changed by someone else since it was read
    (expected_version differs). Nothing was changed. .current_version: the stored version,
    or None when the record no longer exists or is deleted."""

    def __init__(self, current_version=None):
        self.current_version = current_version
        super().__init__('This record was changed by someone else since it was loaded. '
                         'Nothing was changed; reload it and try again.')


class InvalidTransition(InvalidValue):
    """A job (or job device) state change that is not allowed, e.g. a finished job
    changing again. Nothing was changed."""


class DeviceLockHeld(RepositoryError):
    """Another operation holds this device's lock. Nothing was changed.
    .lock = {'device_id', 'purpose', 'job_id', 'holder_user_id', 'expires_at'} (never the
    lease id of the holder)."""

    def __init__(self, lock):
        self.lock = {k: lock.get(k) for k in ('device_id', 'purpose', 'job_id',
                                               'holder_user_id', 'expires_at')}
        super().__init__(f"Device {self.lock['device_id']} is in use by another operation "
                         f"({self.lock['purpose']}) until {self.lock['expires_at']}. "
                         f"Nothing was changed.")
