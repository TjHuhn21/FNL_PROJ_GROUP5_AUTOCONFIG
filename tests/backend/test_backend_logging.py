"""Phase 4B: log redaction. Secrets in messages, arguments, tracebacks, headers, query
strings and setting values are replaced with [REDACTED]; request bodies are not logged."""
import io
import logging

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from backend import logging_config as L
from backend.app import create_app
from backend.settings import parse_settings

PASSWORD = 'Hunter2-Device-Pass'
TOKEN = 'tok_9f8e7d6c5b4a3f2e1d0c'
FERNET_TOKEN = 'gAAAAABl' + 'x' * 60 + '=='


@pytest.mark.parametrize('text, secret', [
    (f'login password={PASSWORD} ok', PASSWORD),
    (f'password: {PASSWORD}', PASSWORD),
    (f'{{"password": "{PASSWORD}", "user": "admin"}}', PASSWORD),
    (f"{{'session_token': '{TOKEN}'}}", TOKEN),
    (f'BACKEND_DB_PASSWORD={PASSWORD}', PASSWORD),
    (f'otp_code=123456 sent', '123456'),
    (f'verification_code: 654321', '654321'),
    (f'fernet_key={TOKEN}', TOKEN),
    (f'Authorization: Bearer {TOKEN}', TOKEN),
    (f'authorization={TOKEN}', TOKEN),
    (f'sent bearer {TOKEN} to server', TOKEN),
    (f'GET /auth/verify?token={TOKEN}&next=/ HTTP/1.1', TOKEN),
    (f'GET /x?otp=112233&password={PASSWORD} HTTP/1.1', PASSWORD),
    (f'password_enc={FERNET_TOKEN}', FERNET_TOKEN),
    (f'stored {FERNET_TOKEN} in devices', FERNET_TOKEN),
    (f'SMTP_PASSWORD="{PASSWORD}"', PASSWORD),
])
def test_patterns_are_redacted(text, secret):
    out = L.redact(text)
    assert secret not in out and L.REDACTED in out


def test_ordinary_text_is_left_alone():
    text = 'GET /health HTTP/1.1 200; device SW1 (10.0.0.1) is now up; status code 200'
    assert L.redact(text) == text


def test_registered_setting_values_are_redacted_anywhere():
    L.register_secrets(['Plain-Secret-Value-555', 'abc'])       # too short ones are skipped
    out = L.redact('connecting with Plain-Secret-Value-555 to abc')
    assert 'Plain-Secret-Value-555' not in out and out.endswith('to abc')


def make_logger(name='backend.test-redaction'):
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(L.RedactingFormatter('%(levelname)s %(message)s'))
    logger = logging.getLogger(name)
    logger.handlers[:] = [handler]
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    return logger, stream


def test_formatter_redacts_arguments_and_tracebacks():
    logger, stream = make_logger()
    logger.info('device login %s', f'password={PASSWORD}')
    try:
        raise RuntimeError(f'SMTP refused: password={PASSWORD} token={TOKEN}')
    except RuntimeError:
        logger.exception('send failed for %s', 'user@example.com')
    out = stream.getvalue()
    assert PASSWORD not in out and TOKEN not in out
    assert 'Traceback' in out and 'RuntimeError' in out and 'user@example.com' in out


def test_configure_logging_redacts_settings_and_uvicorn_lines(restore_logging, capsys):
    secret = 'Configured-Db-Password-321'
    settings = parse_settings({'BACKEND_DB_ENABLED': 'true', 'BACKEND_DB_HOST': '127.0.0.1',
                               'BACKEND_DB_PORT': '3307', 'BACKEND_DB_USER': 'u',
                               'BACKEND_DB_PASSWORD': secret, 'BACKEND_DB_NAME': 'x_test'})
    L.configure_logging(settings)
    logging.getLogger('backend').warning('connect failed using %s', secret)
    logging.getLogger('uvicorn.access').info('%s - "%s %s HTTP/%s" %d', '127.0.0.1:5000', 'GET',
                                             f'/auth?token={TOKEN}', '1.1', 200)
    err = capsys.readouterr().err
    assert secret not in err and TOKEN not in err
    assert err.count(L.REDACTED) >= 2 and 'connect failed using' in err


def test_requests_bodies_are_not_logged(caplog):
    app = create_app(parse_settings({}))

    class Body(BaseModel):
        email: str
        password: str

    @app.post('/test-only-login')
    def login(body: Body):
        return {'ok': True}
    with caplog.at_level(logging.DEBUG):
        r = TestClient(app).post('/test-only-login',
                                 json={'email': 'a@example.com', 'password': PASSWORD})
    assert r.status_code == 200
    assert PASSWORD not in caplog.text


def test_unexpected_error_log_is_redacted(restore_logging, capsys):
    L.configure_logging(parse_settings({}))
    app = create_app(parse_settings({}))

    @app.get('/test-only-crash')
    def crash():
        raise RuntimeError(f'db connect failed password={PASSWORD}')
    r = TestClient(app, raise_server_exceptions=False).get('/test-only-crash')
    assert r.status_code == 500
    err = capsys.readouterr().err
    assert 'Unhandled error for GET /test-only-crash' in err and PASSWORD not in err
