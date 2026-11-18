"""Backend tests: never read a real backend/.env, never see BACKEND_* values from the
shell running the tests, and keep process-wide logging as it was."""
import logging
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backend import settings as backend_settings  # noqa: E402
from backend import logging_config  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_backend_env(monkeypatch, tmp_path):
    for name in list(os.environ):
        if name.startswith(backend_settings.PREFIX):
            monkeypatch.delenv(name)
    # Any accidental load_settings() reads this missing file, never backend/.env.
    monkeypatch.setenv(backend_settings.ENV_FILE_VARIABLE, str(tmp_path / 'absent.env'))
    monkeypatch.setattr(backend_settings, 'DEFAULT_ENV_FILE', tmp_path / 'absent-default.env')
    yield
    logging_config.clear_registered_secrets()


@pytest.fixture
def restore_logging():
    """For tests that call configure_logging(): put the logging setup back afterwards."""
    root = logging.getLogger()
    names = ('uvicorn', 'uvicorn.error', 'uvicorn.access', 'backend', 'py.warnings')
    saved_root = (root.level, list(root.handlers))
    saved = {n: (logging.getLogger(n).level, list(logging.getLogger(n).handlers),
                 logging.getLogger(n).propagate) for n in names}
    yield
    root.handlers[:] = saved_root[1]
    root.setLevel(saved_root[0])
    for n, (level, handlers, propagate) in saved.items():
        logger = logging.getLogger(n)
        logger.setLevel(level)
        logger.handlers[:] = handlers
        logger.propagate = propagate
    logging.captureWarnings(False)
