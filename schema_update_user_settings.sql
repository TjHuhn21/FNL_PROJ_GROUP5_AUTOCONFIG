-- NetCommand database update: small per-user settings (for now: whether the welcome tour
-- was completed or skipped, and the Overview's getting-started checklist). Run it ONCE on
-- an existing database, as the database administrator (root):
--
--     mysql -u root -p --port 3307 < schema_update_user_settings.sql
--
-- The app's own account (netcommand_app) already has SELECT / INSERT / UPDATE on
-- netcommand.*, so nothing else is needed. Until this update is run the app still works:
-- the flags are then kept in the local settings file of this computer instead.
-- New databases get the table from schema.sql.

USE netcommand;

CREATE TABLE IF NOT EXISTS user_settings (
  user_key    VARCHAR(190) NOT NULL,          -- the account's id on the NetCommand server
  name        VARCHAR(64)  NOT NULL,
  value       VARCHAR(255) NOT NULL,
  updated_at  TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (user_key, name)
) ENGINE=InnoDB;
