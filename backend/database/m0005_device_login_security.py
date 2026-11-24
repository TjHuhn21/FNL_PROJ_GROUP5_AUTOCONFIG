"""Migration 0005: the security lockout for failed DEVICE logins (additive only).

Creates two tables; the users table is NOT changed (the migration account has no ALTER on
it, on purpose). The rules are in backend/auth/device_lockout.py.

  security_device_login_state   one row per user who ever reported a device login:
                                the failure count and when its 10-minute window started,
                                locked_until (temporary lock), permanent_locked_at (the
                                admin-only lock: reported as status 'locked_by_security'),
                                lockouts_reset_at (an unlock: older lockouts stop counting)
  security_lockouts             append-only: every lockout with its time and kind, so the
                                lockouts of the last 24 hours can be counted; kept as history

Every timestamp is DATETIME(6) in UTC, written by the backend as UTC_TIMESTAMP(6). The
runtime account gets SELECT/INSERT/UPDATE on the state and only SELECT/INSERT on the
lockouts (no UPDATE, no DELETE anywhere).

MySQL note: CREATE TABLE commits implicitly; the runner reports a failure precisely.
"""
VERSION = 5
NAME = 'device_login_security'

TABLES = ('security_device_login_state', 'security_lockouts')

UP = [
    """CREATE TABLE security_device_login_state (
  user_id             BIGINT UNSIGNED NOT NULL,
  failed_count        SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  first_failed_at     DATETIME(6) NULL,
  locked_until        DATETIME(6) NULL,
  permanent_locked_at DATETIME(6) NULL,
  lockouts_reset_at   DATETIME(6) NULL,
  updated_at          DATETIME(6) NOT NULL,
  PRIMARY KEY (user_id),
  CONSTRAINT fk_security_state_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_security_state_count CHECK (failed_count <= 100)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE security_lockouts (
  id                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id             BIGINT UNSIGNED NOT NULL,
  created_at          DATETIME(6) NOT NULL,
  kind                ENUM('temporary','permanent') NOT NULL,
  locked_until        DATETIME(6) NULL,
  device_ip           VARCHAR(45) NULL,
  reason              VARCHAR(100) NULL,
  PRIMARY KEY (id),
  KEY ix_security_lockouts_user (user_id, created_at),
  CONSTRAINT fk_security_lockouts_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",
]

DOWN = [f'DROP TABLE IF EXISTS {t}' for t in reversed(TABLES)]
