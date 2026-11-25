-- NetCommand database tables (MySQL 8.4). Tables only: run it once on a new database.
-- Database users and privileges are NOT created here: the database administrator
-- configures them separately (the app connects as the restricted netcommand_app user
-- set in .env). Every CREATE statement uses IF NOT EXISTS, so existing tables and
-- data are left untouched.

CREATE DATABASE IF NOT EXISTS netcommand CHARACTER SET utf8mb4;
USE netcommand;

CREATE TABLE IF NOT EXISTS devices (
  id           INT AUTO_INCREMENT PRIMARY KEY,
  name         VARCHAR(80)  NOT NULL,
  ip           VARCHAR(15)  NOT NULL UNIQUE,
  mac          VARCHAR(17)  NOT NULL DEFAULT '',
  type         ENUM('switch','router','unknown') NOT NULL DEFAULT 'unknown',
  -- what the last scan detected (NULL: added by hand); existing databases: run
  -- schema_update_detected_type.sql once
  detected_type ENUM('switch','router','unknown') NULL DEFAULT NULL,
  managed      TINYINT(1)   NOT NULL DEFAULT 0,
  status       ENUM('up','down') NOT NULL DEFAULT 'up',
  username     VARCHAR(50)  NOT NULL DEFAULT '',
  password_enc VARCHAR(255) NOT NULL DEFAULT '',
  is_deleted   TINYINT(1)   NOT NULL DEFAULT 0,
  created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at   DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS links (
  id       INT AUTO_INCREMENT PRIMARY KEY,
  device_a VARCHAR(80) NOT NULL,
  port_a   VARCHAR(40) NOT NULL,
  device_b VARCHAR(80) NOT NULL,
  port_b   VARCHAR(40) NOT NULL,
  UNIQUE KEY uq_link (device_a, port_a, device_b, port_b)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS findings (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  device_id  INT NOT NULL,
  rule       VARCHAR(60) NOT NULL,
  severity   ENUM('high','medium','low') NOT NULL,
  message    TEXT NOT NULL,
  commands   TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS status_events (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  device_id  INT NOT NULL,
  kind       VARCHAR(30) NOT NULL,
  detail     TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Small per-user settings (the welcome tour was completed, the getting-started checklist).
-- Existing databases: run schema_update_user_settings.sql once.
CREATE TABLE IF NOT EXISTS user_settings (
  user_key    VARCHAR(190) NOT NULL,
  name        VARCHAR(64)  NOT NULL,
  value       VARCHAR(255) NOT NULL,
  updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_key, name)
) ENGINE=InnoDB;

-- The saved Console history: append-only (the triggers refuse every UPDATE and DELETE).
-- Existing databases: run schema_update_console_log.sql once.
CREATE TABLE IF NOT EXISTS console_log (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  created_at  DATETIME(3)  NOT NULL,
  user_label  VARCHAR(120) NOT NULL,
  category    VARCHAR(20)  NOT NULL,
  device      VARCHAR(80)  NULL,
  device_ip   VARCHAR(45)  NULL,
  message     TEXT         NOT NULL,
  result      VARCHAR(500) NULL,
  level       ENUM('info','ok','warn','error') NOT NULL,
  tags        VARCHAR(100) NOT NULL DEFAULT '',
  detail      MEDIUMTEXT   NULL,
  KEY ix_console_log_time (created_at),
  KEY ix_console_log_user (user_label),
  KEY ix_console_log_device (device)
) ENGINE=InnoDB;

CREATE TRIGGER IF NOT EXISTS console_log_no_update BEFORE UPDATE ON console_log
  FOR EACH ROW SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'console_log is append-only: entries cannot be changed';

CREATE TRIGGER IF NOT EXISTS console_log_no_delete BEFORE DELETE ON console_log
  FOR EACH ROW SIGNAL SQLSTATE '45000'
  SET MESSAGE_TEXT = 'console_log is append-only: entries cannot be deleted';

CREATE TABLE IF NOT EXISTS config_logs (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  device_id  INT NOT NULL,
  action     VARCHAR(100) NOT NULL,
  status     ENUM('success','failed') NOT NULL,
  details    TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (device_id) REFERENCES devices(id)
) ENGINE=InnoDB;
