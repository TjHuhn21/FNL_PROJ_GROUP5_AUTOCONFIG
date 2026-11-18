"""Migration 0001: authentication tables (additive only; tables, no triggers).

Creates users, email_challenges, sessions and audit_log. Never touches the five
application tables (devices, links, findings, status_events, config_logs) and never uses
IF NOT EXISTS: an existing table is an error (the runner reports it before anything runs),
never silently recreated.

Rules built into the tables:
  * every timestamp is DATETIME(6) in UTC, written by the backend as UTC_TIMESTAMP(6);
  * users.password_hash must start with $argon2id$ (compared case-sensitively): a
    plaintext password cannot be stored by accident;
  * email_challenges.code_hmac and sessions.token_hash are 64-character hex digests: the
    OTP code and the session token themselves are never stored;
  * audit_log has no foreign key (history outlives accounts).

The audit_log protection triggers are NOT created here: with binary logging on, creating
a trigger needs more privilege than the migration account should have. They are a
separate administrator step (backend/database/audit_triggers.py), and `migrate status`
reports whether they are installed. The runtime account is kept from changing audit rows
by its grants (no UPDATE/DELETE on audit_log).

MySQL note: CREATE TABLE / DROP TABLE commit implicitly. This migration is not one
transaction; the runner reports exactly how far it got if a statement fails.
"""
VERSION = 1
NAME = 'auth_tables'

# Created in this order; dropped in the reverse order (foreign keys).
TABLES = ('users', 'email_challenges', 'sessions', 'audit_log')

UP = [
    """CREATE TABLE users (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  email             VARCHAR(254) NOT NULL,
  email_normalized  VARCHAR(254) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  full_name         VARCHAR(100) NOT NULL,
  password_hash     VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  role              ENUM('admin','operator','viewer') NOT NULL DEFAULT 'viewer',
  status            ENUM('pending_verification','pending_approval','active','rejected','disabled')
                    NOT NULL DEFAULT 'pending_verification',
  email_verified_at DATETIME(6) NULL,
  approved_by       BIGINT UNSIGNED NULL,
  approved_at       DATETIME(6) NULL,
  failed_logins     INT UNSIGNED NOT NULL DEFAULT 0,
  locked_until      DATETIME(6) NULL,
  created_at        DATETIME(6) NOT NULL,
  updated_at        DATETIME(6) NOT NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_users_email (email_normalized),
  KEY ix_users_role_status (role, status),
  KEY ix_users_status (status),
  CONSTRAINT fk_users_approved_by FOREIGN KEY (approved_by) REFERENCES users (id)
    ON DELETE RESTRICT ON UPDATE RESTRICT,
  CONSTRAINT ck_users_password_hash CHECK (password_hash LIKE '$argon2id$%'),
  CONSTRAINT ck_users_email_normalized CHECK (email_normalized = LOWER(email_normalized))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE email_challenges (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  public_id         VARCHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  user_id           BIGINT UNSIGNED NOT NULL,
  purpose           ENUM('register','login') NOT NULL,
  code_hmac         CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  attempts          SMALLINT UNSIGNED NOT NULL DEFAULT 0,
  max_attempts      SMALLINT UNSIGNED NOT NULL DEFAULT 5,
  created_at        DATETIME(6) NOT NULL,
  expires_at        DATETIME(6) NOT NULL,
  consumed_at       DATETIME(6) NULL,
  invalidated_at    DATETIME(6) NULL,
  requester_ip      VARCHAR(45) NULL,
  workstation_label VARCHAR(100) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_email_challenges_public_id (public_id),
  KEY ix_email_challenges_user (user_id, purpose, created_at),
  CONSTRAINT fk_email_challenges_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT ck_email_challenges_hmac CHECK (CHAR_LENGTH(code_hmac) = 64),
  CONSTRAINT ck_email_challenges_expiry CHECK (expires_at > created_at),
  CONSTRAINT ck_email_challenges_attempts CHECK (max_attempts BETWEEN 1 AND 20)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE sessions (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  user_id           BIGINT UNSIGNED NOT NULL,
  token_hash        CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
  workstation_label VARCHAR(100) NULL,
  client_ip         VARCHAR(45) NULL,
  created_at        DATETIME(6) NOT NULL,
  last_seen_at      DATETIME(6) NOT NULL,
  expires_at        DATETIME(6) NOT NULL,
  revoked_at        DATETIME(6) NULL,
  revoked_reason    VARCHAR(40) NULL,
  PRIMARY KEY (id),
  UNIQUE KEY uq_sessions_token_hash (token_hash),
  KEY ix_sessions_user (user_id, revoked_at),
  CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON DELETE CASCADE ON UPDATE RESTRICT,
  CONSTRAINT ck_sessions_token_hash CHECK (CHAR_LENGTH(token_hash) = 64),
  CONSTRAINT ck_sessions_expiry CHECK (expires_at > created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",

    """CREATE TABLE audit_log (
  id                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  created_at        DATETIME(6) NOT NULL,
  actor_user_id     BIGINT UNSIGNED NULL,
  actor_email       VARCHAR(254) NULL,
  action            VARCHAR(64) NOT NULL,
  target_type       VARCHAR(32) NULL,
  target_id         VARCHAR(64) NULL,
  outcome           ENUM('success','failure','denied') NOT NULL,
  client_ip         VARCHAR(45) NULL,
  workstation_label VARCHAR(100) NULL,
  detail            VARCHAR(1000) NULL,
  PRIMARY KEY (id),
  KEY ix_audit_log_created (created_at),
  KEY ix_audit_log_actor (actor_user_id, created_at),
  KEY ix_audit_log_action (action, created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci""",
]

# Only this migration's own tables, in reverse order; IF EXISTS so an interrupted rollback
# is finished by running it again. Dropping audit_log also removes its triggers.
DOWN = [f'DROP TABLE IF EXISTS {t}' for t in reversed(TABLES)]
