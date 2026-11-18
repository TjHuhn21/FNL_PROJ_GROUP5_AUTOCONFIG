"""The NetCommand backend application (FastAPI).

  GET /health   liveness only: the process is running (never touches the database)
  GET /ready    readiness: the runtime account can reach the database and the schema
                matches this code (read-only; backend/database/health.py)
No authentication or email yet, and migrations never run on startup.

Start it with:  python -m backend          (see backend/README.md)
Or with uvicorn directly:  uvicorn --factory backend.app:app_factory

create_app() takes its settings as an argument (tests pass their own). Nothing reads
settings, files or the network when this module is imported.
"""
import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from backend import __version__
from backend.logging_config import configure_logging
from backend.settings import Settings, load_settings

log = logging.getLogger('backend')


def create_app(settings: Settings = None, *, setup_logging=False):
    """The FastAPI application. settings: backend Settings (default: load_settings()).
    setup_logging: configure process-wide logging (the server does; tests do not)."""
    if settings is None:
        settings = load_settings()
    if setup_logging:
        configure_logging(settings)
    app = FastAPI(title='NetCommand backend', version=__version__,
                  docs_url='/docs' if settings.docs_enabled else None,
                  redoc_url=None,
                  openapi_url='/openapi.json' if settings.docs_enabled else None)
    app.state.settings = settings

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        """422 without echoing what was sent: FastAPI's default reply repeats the
        submitted values ('input'), which later could be a password or an OTP."""
        errors = [{'loc': list(e.get('loc', ())), 'msg': e.get('msg', ''),
                   'type': e.get('type', '')} for e in exc.errors()]
        return JSONResponse(status_code=422, content={'detail': errors})

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, exc: Exception):
        """A bug: logged (redacted) on the server; the client gets no details."""
        log.exception('Unhandled error for %s %s', request.method, request.url.path)
        return JSONResponse(status_code=500, content={'detail': 'Internal server error'})

    @app.get('/health', status_code=200, tags=['health'])
    def health():
        """The backend process is running. Touches no database or other service and
        reveals nothing about the system."""
        return {'status': 'ok'}

    @app.get('/ready', tags=['health'], responses={503: {'description': 'Not ready'}})
    def ready():
        """Can the backend use its database? 200 {"status": "ready"}, or 503 with a
        generic reason code. Read-only (runtime account, SELECT only); never migrates.
        The database code is imported here, not at module import, so GET /health never
        loads it."""
        from backend.database.health import check_database
        result = check_database(app.state.settings)
        return JSONResponse(status_code=200 if result.ready else 503, content=result.public(),
                            headers={'Cache-Control': 'no-store'})

    return app


def app_factory():
    """For `uvicorn --factory backend.app:app_factory`: settings from the backend's own
    env file and environment, and the backend's redacting logging."""
    return create_app(setup_logging=True)
