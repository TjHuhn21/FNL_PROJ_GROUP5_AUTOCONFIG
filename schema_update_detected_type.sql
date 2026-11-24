-- NetCommand database update: remember the device type the scan detected.
-- Run it ONCE on an existing database, as the database administrator (root), because the
-- app's own account (netcommand_app) may not change tables:
--
--     mysql -u root -p --port 3307 < schema_update_detected_type.sql
--
-- devices.type           the type the app uses (the user may change it on the Devices page)
-- devices.detected_type  what the last scan detected; NULL: never scanned (added by hand)
--
-- Existing devices get detected_type = their current type (they came from earlier scans),
-- so a rescan keeps working as before. Until this update is run the app still works: scans
-- then simply do not record the detected type. New databases get the column from schema.sql.

USE netcommand;

ALTER TABLE devices
  ADD COLUMN detected_type ENUM('switch','router','unknown') NULL DEFAULT NULL AFTER type;

UPDATE devices SET detected_type = type WHERE detected_type IS NULL;
