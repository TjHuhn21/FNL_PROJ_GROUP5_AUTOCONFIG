"""Backend logging with secret redaction.

Every log line goes through RedactingFormatter, which formats the record (message,
arguments AND any traceback) and then removes secrets from the finished text:
  * values after sensitive names: password=..., "token": "...", BACKEND_DB_PASSWORD=...,
    otp_code: ..., fernet_key=..., ... (in key=value, key: value and JSON forms);
  * Authorization headers and bearer tokens;
  * sensitive query-string parameters (?token=...&password=...);
  * Fernet tokens (encrypted device passwords: they start with gAAAAA);
  * the exact values of every secret setting (register_secrets(), done at startup).

Nothing here logs request bodies: no body-logging middleware exists, and the access log
shows only the request line, whose query string is redacted like any other text.
This is a first layer, not a guarantee: code must still never log secrets on purpose.
"""
import logging
import logging.config
import re
import threading

REDACTED = '[REDACTED]'

_NAMES = (r'(?:password|passwd|pwd|passphrase|secret|client_secret|token|access_token|'
          r'refresh_token|session_token|otp|otp_code|verification_code|login_code|pepper|'
          r'fernet_key|api_key|secret_key|private_key)')
# name, optional closing quote, = or :, optional opening quote ... then the value
_KEY_VALUE = re.compile(rf'(?i)(\b[\w-]*{_NAMES}["\']?\s*[=:]\s*["\']?)([^"\'\s,;&}}\]]+)')
_AUTH_HEADER = re.compile(r'(?i)(\bauthorization["\']?\s*[=:]\s*["\']?)(?:(bearer|basic|token)\s+)?'
                          r'([^"\'\s,;]+)')
_BEARER = re.compile(r'(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+')
_FERNET_TOKEN = re.compile(r'gAAAAA[A-Za-z0-9_\-]{20,}={0,2}')
MIN_SECRET_LENGTH = 4        # shorter registered values are ignored (too many false hits)

_secrets = set()
_lock = threading.Lock()


def register_secrets(values):
    """Remember exact secret values (from the settings) so they are always redacted."""
    with _lock:
        _secrets.update(v for v in values if isinstance(v, str) and len(v) >= MIN_SECRET_LENGTH)


def clear_registered_secrets():
    with _lock:
        _secrets.clear()


def redact(text):
    """text with every recognised secret replaced by [REDACTED]."""
    if not text:
        return text
    with _lock:
        known = sorted(_secrets, key=len, reverse=True)   # longest first
    for value in known:
        text = text.replace(value, REDACTED)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + (m.group(2) + ' ' if m.group(2) else '')
                            + REDACTED, text)
    text = _BEARER.sub(lambda m: f'{m.group(1)} {REDACTED}', text)
    text = _KEY_VALUE.sub(lambda m: m.group(1) + REDACTED, text)
    text = _FERNET_TOKEN.sub(REDACTED, text)
    return text


class RedactingFormatter(logging.Formatter):
    """A Formatter whose whole output (message, arguments, traceback) is redacted."""

    def format(self, record):
        return redact(super().format(record))

    def formatException(self, ei):
        return redact(super().formatException(ei))


FORMAT = '%(asctime)s %(levelname)-8s %(name)s: %(message)s'


def logging_config(level='INFO'):
    """dictConfig for the backend: one redacting handler on the root logger; uvicorn's
    loggers pass their records to it (no handlers of their own)."""
    return {
        'version': 1,
        'disable_existing_loggers': False,
        'formatters': {'redacting': {'()': RedactingFormatter, 'fmt': FORMAT}},
        'handlers': {'console': {'class': 'logging.StreamHandler', 'formatter': 'redacting',
                                 'stream': 'ext://sys.stderr'}},
        'root': {'level': level, 'handlers': ['console']},
        'loggers': {name: {'level': level, 'handlers': [], 'propagate': True}
                    for name in ('uvicorn', 'uvicorn.error', 'uvicorn.access', 'backend')},
    }


def configure_logging(settings):
    """Set up logging for the backend process and register the secret values."""
    register_secrets(settings.secret_values())
    logging.config.dictConfig(logging_config(settings.log_level))
    logging.captureWarnings(True)


__all__ = ['REDACTED', 'redact', 'register_secrets', 'clear_registered_secrets',
           'RedactingFormatter', 'logging_config', 'configure_logging']
