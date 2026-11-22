"""Migration 0002: shared application data (additive only; new prefixed tables).

Creates app_devices, app_device_credentials, app_links, app_findings, app_status_events
and app_config_logs in the BACKEND database. The desktop database's own tables (devices,
links, findings, status_events, config_logs) are never named, read, altered or reused: the
migration guard (migrations.APP_TABLES) still refuses any migration that names them.

Rules built into the tables:
  * every timestamp is DATETIME(6) in UTC, written by the backend as UTC_TIMESTAMP(6);
  * devices are only ever soft-deleted (is_deleted = 1); every reference to app_devices is
    ON DELETE RESTRICT, so history (findings, events, logs, credentials) can never be
    removed by deleting a device row;
  * app_devices.ip is UNIQUE for every row, deleted ones included (as the desktop store:
    re-adding a deleted device's IP is refused; restoring it is a separate, explicit step);
  * active device names are unique ignoring capital letters, enforced by the database too:
    active_name_key is a STORED generated column, LOWER(name) while the device is active and
    NULL once deleted, with a UNIQUE index (MySQL allows any number of NULLs). Names are
    ASCII only (letters, digits, . _ -, checked by the repository), where MySQL's LOWER()
    and Python's str.lower() agree;
  * app_devices.version is the optimistic-locking counter: every change adds 1;
  * created_by / updated_by / user_id are users.id of the account that acted, or NULL
    (imported legacy records, or the backend itself);
  * credentials live in their own table (one row per device, at most). password_enc must
    look like a Fernet token (it starts with gAAAAA): a plaintext password cannot be stored
    by accident. Device queries never select from it;
  * app_links keep the device NAMES and ports exactly as the desktop does, plus nullable
    device ids, filled when the name matches an active device (a legacy link whose names
    match no device keeps NULL ids);
  * findings are replaced as a snapshot without deleting anything: the current snapshot is
    the rows with superseded_at NULL; a new snapshot marks the old rows superseded (so the
    runtime account needs no DELETE anywhere);
  * app_status_events and app_config_logs are append-only (the runtime account gets only
    SELECT and INSERT on them, see privileges.py).

job_id columns: app_jobs is created by migration 0003, so the job_id columns here are
plain indexed columns without a foreign key (a migration may only drop its own tables, so
0003 cannot add a constraint to these). The repository checks that a given job exists.

MySQL note: CREATE TABLE commits implicitly. This migration is not one transaction; the
runner reports exactly how far it got if a statement fails.
"""
VERSION = 2
NAME = 'app_tables'

# Created in this order; dropped in the reverse order (foreign keys).
TABLES = ('app_devices', 'app_device_credentials', 'app_links', 'app_findings',
          'app_status_events', 'app_config_logs')

UP = [
    """CREATE TABLE app_devices (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  name              VARCHAR(80) NOT NULL,
  ip                VARCHAR(15) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  mac               VARCHAR(17) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL DEFAULT '',
  type              ENUM('switch','router','unknown') NOT NULL DEFAULT 'unknown',
  managed           TINYINT(1) NOT NULL DEFAULT 0,
  status            ENUM('up','down') NOT NULL DEFAULT 'up',
  is_deleted        TINYINT(1) NOT NULL DEFAULT 0,
  version           INT UNSIGNED NOT NULL DEFAULT 1,
  active_name_key   VARCHAR(80) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
                    GENERATED ALWAYS AS (IF(is_deleted = 0, LOWER(name), NULL)) STORED,
  created_at        DATETIME(6) NOT NULL,
  updated_at        DATETIME(6) NOT NULL,
  deleted_at        DATETIME(6) NULL,
  created_by        BIGINT UNSIGNED NULL,
  updated_by        BIGINT UNSIGNED NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_app_devices_ip (ip),
  UNIQUE KEY uq_app_devices_active_name (active_name_key),
  KEY ix_app_devices_active (is_deleted, name),
  CONSTRAINT fk_app_devices_created_by FOREIGN KEY (created_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_devices_updated_by FOREIGN KEY (updated_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_app_devices_name CHECK (CHAR_LENGTH(name) BETWEEN 1 AND 80),
  CONSTRAINT ck_app_devices_ip CHECK (CHAR_LENGTH(ip) BETWEEN 7 AND 15),
  CONSTRAINT ck_app_devices_flags CHECK (managed IN (0, 1) AND is_deleted IN (0, 1)),
  CONSTRAINT ck_app_devices_version CHECK (version >= 1),
  CONSTRAINT ck_app_devices_deleted_at CHECK ((is_deleted = 1) = (deleted_at IS NOT NULL))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_device_credentials (
  device_id         BIGINT UNSIGNED NOT NULL,
  username          VARCHAR(50) NOT NULL,
  password_enc      VARCHAR(255) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  key_id            VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'k1',
  created_at        DATETIME(6) NOT NULL,
  updated_at        DATETIME(6) NOT NULL,
  updated_by        BIGINT UNSIGNED NULL,
  PRIMARY KEY (device_id),
  CONSTRAINT fk_app_device_credentials_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_device_credentials_updated_by FOREIGN KEY (updated_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_app_device_credentials_username CHECK (CHAR_LENGTH(username) BETWEEN 1 AND 50),
  CONSTRAINT ck_app_device_credentials_token CHECK (password_enc LIKE 'gAAAAA%'
    AND CHAR_LENGTH(password_enc) BETWEEN 100 AND 255),
  CONSTRAINT ck_app_device_credentials_key_id CHECK (CHAR_LENGTH(key_id) BETWEEN 1 AND 16)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_links (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_a          VARCHAR(80) NOT NULL,
  port_a            VARCHAR(40) NOT NULL,
  device_b          VARCHAR(80) NOT NULL,
  port_b            VARCHAR(40) NOT NULL,
  device_a_id       BIGINT UNSIGNED NULL,
  device_b_id       BIGINT UNSIGNED NULL,
  created_at        DATETIME(6) NOT NULL,
  created_by        BIGINT UNSIGNED NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_app_links (device_a, port_a, device_b, port_b),
  KEY ix_app_links_device_a (device_a_id),
  KEY ix_app_links_device_b (device_b_id),
  CONSTRAINT fk_app_links_device_a FOREIGN KEY (device_a_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_links_device_b FOREIGN KEY (device_b_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_links_created_by FOREIGN KEY (created_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_findings (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id         BIGINT UNSIGNED NOT NULL,
  rule              VARCHAR(60) NOT NULL,
  severity          ENUM('high','medium','low') NOT NULL,
  message           TEXT NOT NULL,
  commands          TEXT NULL,
  created_at        DATETIME(6) NOT NULL,
  superseded_at     DATETIME(6) NULL,
  created_by        BIGINT UNSIGNED NULL,
  job_id            BIGINT UNSIGNED NULL,
  PRIMARY KEY (id),
  KEY ix_app_findings_current (superseded_at, severity, id),
  KEY ix_app_findings_device (device_id),
  KEY ix_app_findings_job (job_id),
  CONSTRAINT fk_app_findings_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_findings_created_by FOREIGN KEY (created_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_status_events (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id         BIGINT UNSIGNED NOT NULL,
  kind              VARCHAR(30) NOT NULL,
  detail            TEXT NULL,
  source            ENUM('monitor','user','job','legacy') NOT NULL DEFAULT 'monitor',
  created_at        DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  KEY ix_app_status_events_device (device_id, id),
  KEY ix_app_status_events_created (created_at),
  CONSTRAINT fk_app_status_events_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE app_config_logs (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id         BIGINT UNSIGNED NOT NULL,
  action            VARCHAR(100) NOT NULL,
  status            ENUM('success','failed') NOT NULL,
  details           TEXT NULL,
  created_at        DATETIME(6) NOT NULL,
  user_id           BIGINT UNSIGNED NULL,
  job_id            BIGINT UNSIGNED NULL,
  PRIMARY KEY (id),
  KEY ix_app_config_logs_device (device_id, id),
  KEY ix_app_config_logs_user (user_id, id),
  KEY ix_app_config_logs_job (job_id),
  CONSTRAINT fk_app_config_logs_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_config_logs_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",
]

# Only this migration's own tables, in reverse order; IF EXISTS so an interrupted rollback
# is finished by running it again.
DOWN = [f'DROP TABLE IF EXISTS {t}' for t in reversed(TABLES)]
