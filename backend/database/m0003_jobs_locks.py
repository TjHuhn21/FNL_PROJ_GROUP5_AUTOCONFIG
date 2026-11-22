"""Migration 0003: jobs and device locks (additive only; new prefixed tables).

Creates app_jobs, app_job_devices, app_job_events and app_device_locks. Schema only: no
job runner and no device operation exists yet (later phases).

Rules built into the tables:
  * a job's state is one of queued, running, succeeded, failed, cancelled, interrupted
    (the allowed transitions are checked by the repository: a finished job never changes);
  * app_jobs.params is JSON for non-secret options only; the repository refuses keys that
    look like secrets (password, secret, token, key, ...);
  * app_job_events is append-only (the runtime account gets only SELECT and INSERT); each
    event has a per-job sequence number (UNIQUE (job_id, seq)) and its message is masked and
    length-limited by the repository before it is written (VARCHAR(2000) here);
  * app_device_locks has one row per device (PRIMARY KEY device_id), so a device can have
    at most one lock. The lock is held while released_at is NULL and expires_at is in the
    future; an expired or released row is taken over by the next acquire (UPDATE, never
    DELETE). lease_id identifies one acquisition, so only its holder renews or releases it.

MySQL note: CREATE TABLE commits implicitly. This migration is not one transaction; the
runner reports exactly how far it got if a statement fails.
"""
VERSION = 3
NAME = 'jobs_locks'

TABLES = ('app_jobs', 'app_job_devices', 'app_job_events', 'app_device_locks')

_STATES = "'queued','running','succeeded','failed','cancelled','interrupted'"

UP = [
    f"""CREATE TABLE app_jobs (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  kind              VARCHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  state             ENUM({_STATES}) NOT NULL DEFAULT 'queued',
  requested_by      BIGINT UNSIGNED NULL,
  params            JSON NULL,
  summary           VARCHAR(1000) NULL,
  created_at        DATETIME(6) NOT NULL,
  updated_at        DATETIME(6) NOT NULL,
  started_at        DATETIME(6) NULL,
  finished_at       DATETIME(6) NULL,
  PRIMARY KEY (id),
  KEY ix_app_jobs_state (state, created_at),
  KEY ix_app_jobs_requested_by (requested_by, created_at),
  CONSTRAINT fk_app_jobs_requested_by FOREIGN KEY (requested_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_app_jobs_kind CHECK (CHAR_LENGTH(kind) BETWEEN 1 AND 32),
  CONSTRAINT ck_app_jobs_times CHECK (finished_at IS NULL OR started_at IS NULL
    OR finished_at >= started_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    f"""CREATE TABLE app_job_devices (
  job_id            BIGINT UNSIGNED NOT NULL,
  device_id         BIGINT UNSIGNED NOT NULL,
  state             ENUM({_STATES}) NOT NULL DEFAULT 'queued',
  message           VARCHAR(1000) NULL,
  updated_at        DATETIME(6) NOT NULL,
  PRIMARY KEY (job_id, device_id),
  KEY ix_app_job_devices_device (device_id, job_id),
  CONSTRAINT fk_app_job_devices_job FOREIGN KEY (job_id) REFERENCES app_jobs (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_job_devices_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_job_events (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  job_id            BIGINT UNSIGNED NOT NULL,
  seq               INT UNSIGNED NOT NULL,
  device_id         BIGINT UNSIGNED NULL,
  kind              ENUM('info','command','output','warning','error','state') NOT NULL,
  message           VARCHAR(2000) NOT NULL,
  created_at        DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_app_job_events_seq (job_id, seq),
  KEY ix_app_job_events_device (device_id),
  CONSTRAINT fk_app_job_events_job FOREIGN KEY (job_id) REFERENCES app_jobs (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_job_events_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_app_job_events_seq CHECK (seq >= 1)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_device_locks (
  device_id         BIGINT UNSIGNED NOT NULL,
  lease_id          CHAR(32) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  job_id            BIGINT UNSIGNED NULL,
  holder_user_id    BIGINT UNSIGNED NULL,
  purpose           VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  acquired_at       DATETIME(6) NOT NULL,
  expires_at        DATETIME(6) NOT NULL,
  released_at       DATETIME(6) NULL,
  PRIMARY KEY (device_id),
  UNIQUE KEY uq_app_device_locks_lease (lease_id),
  KEY ix_app_device_locks_job (job_id),
  KEY ix_app_device_locks_expires (expires_at),
  CONSTRAINT fk_app_device_locks_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_device_locks_job FOREIGN KEY (job_id) REFERENCES app_jobs (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_device_locks_holder FOREIGN KEY (holder_user_id) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_app_device_locks_lease CHECK (CHAR_LENGTH(lease_id) = 32),
  CONSTRAINT ck_app_device_locks_expiry CHECK (expires_at > acquired_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",
]

DOWN = [f'DROP TABLE IF EXISTS {t}' for t in reversed(TABLES)]
