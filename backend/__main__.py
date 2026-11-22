"""python -m backend : start the NetCommand backend (Uvicorn).

Settings come from backend/.env (or the file named by NETCOMMAND_BACKEND_ENV_FILE) and
BACKEND_* environment variables. Invalid settings stop it before it starts, with a
message that names the settings but never shows their values.

Two ways to run it:
  * local development (the default): plain HTTP on 127.0.0.1:8000, this computer only;
  * LAN mode (BACKEND_LAN_MODE=true, see docs/LAN_DEPLOYMENT.md): HTTPS with the
    certificate in BACKEND_TLS_CERT_FILE / BACKEND_TLS_KEY_FILE, usually on port 8443 and
    BACKEND_HOST=0.0.0.0. Settings refuse a non-loopback address without LAN mode, and
    LAN mode without HTTPS, so plain HTTP is never offered to other computers.
HTTPS only accepts TLS 1.2 or newer.
"""
import logging
import ssl
import sys

from backend.settings import SettingsError, describe, load_settings


def server_config(app, settings):
    """The uvicorn.Config for these settings, already loaded, so the TLS context can be
    tightened (minimum TLS 1.2) before the server starts."""
    import uvicorn
    options = dict(host=settings.host, port=settings.port, log_config=None,
                   server_header=False)
    if settings.tls_enabled:
        options.update(ssl_certfile=settings.tls_cert_file, ssl_keyfile=settings.tls_key_file)
    config = uvicorn.Config(app, **options)
    config.load()
    if config.ssl is not None:
        config.ssl.minimum_version = ssl.TLSVersion.TLSv1_2
    return config


def main():
    try:
        settings = load_settings()
    except SettingsError as err:
        print(f'NetCommand backend not started. {err}', file=sys.stderr)
        return 2
    import uvicorn
    from backend.app import create_app
    from backend.logging_config import configure_logging
    configure_logging(settings)
    logging.getLogger('backend').info('Starting NetCommand backend: %s', describe(settings))
    try:
        config = server_config(create_app(settings), settings)
    except (OSError, ssl.SSLError):
        # never the exception's own text: it could quote a file path or key details
        print('NetCommand backend not started: the HTTPS certificate or private key could not '
              'be loaded (check BACKEND_TLS_CERT_FILE and BACKEND_TLS_KEY_FILE).',
              file=sys.stderr)
        return 2
    uvicorn.Server(config).run()
    return 0


if __name__ == '__main__':
    sys.exit(main())
