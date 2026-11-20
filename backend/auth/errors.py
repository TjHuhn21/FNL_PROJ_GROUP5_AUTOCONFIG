"""Errors of the authentication service. str() of each is a fixed message that is safe
to show to a client (never a value, an account detail or an internal error).

Kept in its own module, free of database imports, so the web app can handle these
errors without loading the database layer (GET /health must never load it).
"""


class AuthError(Exception):
    """Base class."""
    public_message = 'The request could not be completed.'

    def __init__(self, message=None):
        super().__init__(message or self.public_message)


class InvalidRequest(AuthError):
    """A value was refused (the message names the problem, never the value)."""


class LoginFailed(AuthError):
    public_message = 'The email address or password is incorrect, or the account is locked.'


class AccountNotActive(AuthError):
    public_message = ('This account cannot sign in: it is waiting for email verification or '
                      'administrator approval, or it has been disabled.')


class CodeInvalid(AuthError):
    public_message = 'The code is wrong, has expired or has already been used.'


class RetryLater(AuthError):
    def __init__(self, retry_after_seconds):
        self.retry_after_seconds = max(1, int(retry_after_seconds))
        super().__init__(f'Too many requests. Try again in {self.retry_after_seconds} seconds.')


class DeliveryFailed(AuthError):
    public_message = 'The code could not be sent. Try again later.'


class NotAuthenticated(AuthError):
    public_message = 'Sign in again.'


class NotPermitted(AuthError):
    public_message = 'You do not have permission to do this.'


class ServiceUnavailable(AuthError):
    """The database, the mail service or the authentication settings are not available.
    The cause is logged on the server (class name only), never sent to the client."""
    public_message = 'Sign-in is temporarily unavailable. Try again later.'
