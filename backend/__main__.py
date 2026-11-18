"""python -m backend : start the NetCommand backend (Uvicorn).

Settings come from backend/.env (or the file named by NETCOMMAND_BACKEND_ENV_FILE) and
BACKEND_* environment variables. Invalid settings stop it before it starts, with a
message that names the settings but never shows their values.

Phase 4B serves plain HTTP on 127.0.0.1 only. HTTPS comes in a later phase; do not
expose this port to other machines until then.
"""
import logging
import sys

from backend.settings import SettingsError, describe, load_settings


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
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port,
                log_config=None, server_header=False)
    return 0


if __name__ == '__main__':
    sys.exit(main())
