"""Migration 0004: device configuration backups (additive only; schema only).

Creates app_device_backups. Nothing creates, reads or restores a backup yet: the SSH
backup job, the encryption workflow and retrieval belong to Phase G.

Rules built into the table:
  * content_enc holds the backup ENCRYPTED with the backend's Fernet key (a running
    configuration contains password hashes and type 7 passwords). The repository refuses
    content that is not a Fernet token, so a plaintext configuration cannot be stored by
    accident, and its listing never returns the content;
  * sha256 is the hex SHA-256 of the plaintext configuration and size_bytes its length, so
    a backup can be compared or verified without decrypting every copy;
  * key_id names the key that encrypted it ('k1' = the existing key), for a future key
    rotation;
  * backups are kept (append-only for the runtime account: SELECT and INSERT only); the
    device reference is ON DELETE RESTRICT, as everywhere (devices are soft-deleted).

MySQL note: CREATE TABLE commits implicitly; the runner reports a failure precisely.
"""
VERSION = 4
NAME = 'device_backups'

TABLES = ('app_device_backups',)

UP = [
    """CREATE TABLE app_device_backups (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  device_id         BIGINT UNSIGNED NOT NULL,
  job_id            BIGINT UNSIGNED NULL,
  kind              ENUM('running','startup') NOT NULL DEFAULT 'running',
  sha256            CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  size_bytes        INT UNSIGNED NOT NULL,
  key_id            VARCHAR(16) CHARACTER SET ascii COLLATE ascii_bin NOT NULL DEFAULT 'k1',
  content_enc       MEDIUMBLOB NOT NULL,
  created_at        DATETIME(6) NOT NULL,
  created_by        BIGINT UNSIGNED NULL,
  PRIMARY KEY (id),
  KEY ix_app_device_backups_device (device_id, created_at),
  KEY ix_app_device_backups_job (job_id),
  CONSTRAINT fk_app_device_backups_device FOREIGN KEY (device_id) REFERENCES app_devices (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_device_backups_job FOREIGN KEY (job_id) REFERENCES app_jobs (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT fk_app_device_backups_created_by FOREIGN KEY (created_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_app_device_backups_sha256 CHECK (CHAR_LENGTH(sha256) = 64),
  CONSTRAINT ck_app_device_backups_size CHECK (size_bytes <= 4194304),
  CONSTRAINT ck_app_device_backups_key_id CHECK (CHAR_LENGTH(key_id) BETWEEN 1 AND 16)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",
]

DOWN = [f'DROP TABLE IF EXISTS {t}' for t in reversed(TABLES)]
