-- NetCommand database update: the saved Console history (who did what, when, on which
-- device, and what happened). Run it ONCE on an existing database, as the database
-- administrator (root):
--
--     mysql -u root -p --port 3307 < schema_update_console_log.sql
--
-- The table is APPEND-ONLY. The two triggers refuse every UPDATE and DELETE, so no
-- account (not even the app's own netcommand_app, which may update and delete the other
-- tables) can change or remove an entry. TRUNCATE and DROP need privileges the app's
-- account does not have. Until this update is run the app still works: the Console then
-- says that its history is not being saved. New databases get it from schema.sql.

USE netcommand;

CREATE TABLE IF NOT EXISTS console_log (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  created_at  DATETIME(3)  NOT NULL,
  user_label  VARCHAR(120) NOT NULL,           -- masked e-mail, or 'system'
  category    VARCHAR(20)  NOT NULL,
  device      VARCHAR(80)  NULL,
  device_ip   VARCHAR(45)  NULL,
  message     TEXT         NOT NULL,           -- secrets and e-mails already masked
  result      VARCHAR(500) NULL,               -- a command's result: OK, FAILED ..., timed out
  level       ENUM('info','ok','warn','error') NOT NULL,
  tags        VARCHAR(100) NOT NULL DEFAULT '',
  detail      MEDIUMTEXT   NULL,               -- full output / before-after (masked)
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
