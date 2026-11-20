"""Phase 4B: GET /health and the application's safe defaults.
No database, network or .env file is used."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import BaseModel

from backend.app import create_app
from backend.settings import load_settings, parse_settings

ROOT = Path(__file__).resolve().parents[2]
SECRET = 'Health-Test-Secret-Value-7781'


def client(settings=None, **kw):
    return TestClient(create_app(settings or parse_settings({})), **kw)


def test_health_returns_200_and_ok():
    r = client().get('/health')
    assert r.status_code == 200
    assert r.json() == {'status': 'ok'}
    assert r.headers['content-type'].startswith('application/json')


def test_health_reveals_nothing_else():
    r = client().get('/health')
    assert set(r.json()) == {'status'}
    body = r.text.lower()
    for word in ('version', 'host', 'python', 'mysql', 'database', 'path', 'user'):
        assert word not in body
    assert 'server' not in {k.lower() for k in r.headers}


def test_health_works_with_no_settings_at_all():
    settings = load_settings(environ={}, use_file=False)           # nothing configured
    assert settings.database is None and settings.smtp is None
    assert settings.fernet_key is None and settings.otp_pepper is None
    assert client(settings).get('/health').json() == {'status': 'ok'}


def test_health_only_answers_get():
    assert client().post('/health').status_code == 405


def test_health_does_not_touch_mysql_or_the_network(monkeypatch):
    import socket
    import pymysql
    attempts = []
    monkeypatch.setattr(pymysql, 'connect', lambda *a, **k: attempts.append('mysql'))
    monkeypatch.setattr(socket, 'create_connection', lambda *a, **k: attempts.append('net'))
    try:
        import db
        monkeypatch.setattr(db, 'get_conn', lambda *a, **k: attempts.append('db.get_conn'))
    except Exception:
        pass
    assert client().get('/health').status_code == 200
    assert attempts == []


def test_backend_never_imports_the_database_layer():
    """In a fresh interpreter: create the app and call /health; the desktop database
    modules (db, db_fake, pymysql) and security.py are never imported."""
    code = ('import json, sys\n'
            'from fastapi.testclient import TestClient\n'
            'from backend.app import create_app\n'
            'from backend.settings import parse_settings\n'
            'r = TestClient(create_app(parse_settings({}))).get("/health")\n'
            'print(json.dumps({"status": r.status_code, "loaded": sorted(m for m in '
            '("db", "db_fake", "pymysql", "security") if m in sys.modules)}))\n')
    env = {k: v for k, v in os.environ.items() if not k.startswith('BACKEND_')}
    env['NETCOMMAND_BACKEND_ENV_FILE'] = str(ROOT / 'tests' / 'backend' / 'no-such.env')
    out = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout.strip().splitlines()[-1]) == {'status': 200, 'loaded': []}


def test_backend_source_has_no_database_imports():
    for path in (ROOT / 'backend').glob('*.py'):
        text = path.read_text(encoding='utf-8')
        for banned in ('import db', 'import db_fake', 'import pymysql', 'from db ',
                       'import security'):
            assert banned not in text, f'{path.name} contains {banned!r}'


def test_docs_are_off_in_production():
    dev = client(parse_settings({}))
    prod = client(parse_settings({'BACKEND_ENV': 'production'}))
    assert dev.get('/docs').status_code == 200
    assert prod.get('/docs').status_code == 404
    assert prod.get('/openapi.json').status_code == 404
    assert prod.get('/health').json() == {'status': 'ok'}


def test_validation_errors_do_not_echo_submitted_values():
    app = create_app(parse_settings({}))

    class Login(BaseModel):
        email: str
        attempts: int

    @app.post('/test-only')
    def test_only(body: Login):
        return {}
    r = TestClient(app).post('/test-only', json={'email': 'a@b.c', 'attempts': SECRET,
                                                  'password': SECRET})
    assert r.status_code == 422
    assert SECRET not in r.text and 'input' not in r.json()['detail'][0]


def test_unexpected_errors_reveal_nothing(caplog):
    app = create_app(parse_settings({}))

    @app.get('/test-only-error')
    def broken():
        raise RuntimeError(f'connect failed password={SECRET}')
    r = TestClient(app, raise_server_exceptions=False).get('/test-only-error')
    assert r.status_code == 500 and r.json() == {'detail': 'Internal server error'}
    assert SECRET not in r.text


def test_nothing_is_configured_at_import(tmp_path):
    """Importing backend.app reads no settings (create_app does): in a fresh interpreter
    whose env file is invalid, the import still succeeds; load_settings() would fail."""
    bad = tmp_path / 'bad.env'
    bad.write_text('BACKEND_PORT=not-a-port\n', encoding='utf-8')
    env = {k: v for k, v in os.environ.items() if not k.startswith('BACKEND_')}
    env['NETCOMMAND_BACKEND_ENV_FILE'] = str(bad)
    code = ('import backend.app\n'
            'from backend.settings import SettingsError, load_settings\n'
            'try:\n    load_settings()\nexcept SettingsError:\n    print("import-ok load-refused")\n')
    out = subprocess.run([sys.executable, '-c', code], cwd=ROOT, env=env,
                         capture_output=True, text=True, timeout=120)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == 'import-ok load-refused'
