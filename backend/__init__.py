"""NetCommand backend (FastAPI). Desktop clients will reach it over HTTPS; it will own
authentication, the database and network operations. Phase 4B: skeleton only.

Separate from the desktop application: its settings come from backend/.env and
BACKEND_* environment variables only (see backend/settings.py)."""
__version__ = '0.1.0'
