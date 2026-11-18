"""Backend database layer (Phase 4C): migrations for the authentication tables and the
authentication repository.

Kept apart from backend.app on purpose: nothing here is imported by the web app yet,
and PyMySQL is only imported when a connection is really opened, so GET /health still
cannot reach MySQL. Migrations are never run on startup: only by the operator with
`python -m backend.database.migrate` (see backend/README.md).
"""
