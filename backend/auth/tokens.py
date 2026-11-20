"""Session tokens: 256 random bits for the client, only their SHA-256 hash in the database.

  issue_session_token()        -> IssuedSessionToken(token, token_hash)
  hash_session_token(token)    -> 64 lower-case hex characters (sessions.token_hash)

The raw token is given to the desktop once (kept in memory there, never on disk) and is
never stored or logged by the backend. A token has 256 bits of entropy, so a plain
SHA-256 (no salt, no slow hash) is enough: it cannot be guessed, and lookups stay fast.
repr() of an IssuedSessionToken hides the token; errors never repeat it.
"""
import hashlib
import re
import secrets
from dataclasses import dataclass, field

TOKEN_BYTES = 32                                 # 256 bits
TOKEN_LENGTH = 43                                # URL-safe base64 of 32 bytes, no padding
_TOKEN = re.compile(r'^[A-Za-z0-9_-]{%d}$' % TOKEN_LENGTH)
_HIDDEN = '[hidden]'


class InvalidSessionToken(ValueError):
    """Not a NetCommand session token. The message never contains it."""


@dataclass(frozen=True)
class IssuedSessionToken:
    token: str = field(repr=False)               # give to the client only
    token_hash: str

    def __repr__(self):
        return f'IssuedSessionToken(token={_HIDDEN}, token_hash={self.token_hash[:8]}...)'

    __str__ = __repr__


def generate_session_token():
    """A new random token: 43 URL-safe characters (256 bits)."""
    return secrets.token_urlsafe(TOKEN_BYTES)


def is_well_formed(token):
    return isinstance(token, str) and bool(_TOKEN.match(token))


def hash_session_token(token):
    """The SHA-256 (hex) to store and look up. InvalidSessionToken for anything that is
    not a well-formed token (check before any database lookup)."""
    if not is_well_formed(token):
        raise InvalidSessionToken('The session token is not valid.')
    return hashlib.sha256(token.encode('ascii')).hexdigest()


def issue_session_token():
    token = generate_session_token()
    return IssuedSessionToken(token=token, token_hash=hash_session_token(token))
