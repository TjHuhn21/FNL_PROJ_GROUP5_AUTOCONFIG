-- =====================================================================
-- NetCommand Phase 0A-1 (Step 2): read-only server inspection
--
-- WHAT THIS SCRIPT SENDS
--   Only SHOW statements for server variables / status / the table cache,
--   SELECTs from information_schema (SCHEMATA and the privilege views), and
--   one session setting (SET SESSION TRANSACTION READ ONLY). There is no
--   CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, GRANT, REVOKE, FLUSH, CHECK,
--   REPAIR, ANALYZE or OPTIMIZE, and no SHOW GRANTS (its output can contain
--   authentication information). No password hash or other secret is selected.
--
-- WHAT IT READS
--   Server variables and status counters, the list of databases, and the
--   privilege views of information_schema (grantee names and privilege names
--   only, no authentication data).
--
-- WHAT IT WRITES
--   Nothing in the database. The MariaDB client's `tee` writes the screen
--   output to the report file in your report folder.
--
-- WHAT IT CANNOT GUARANTEE
--   * It is DESIGNED not to open any table: in MariaDB the privilege tables
--     are loaded into memory at start-up, and the information_schema privilege
--     views are answered from that in-memory copy; SCHEMATA comes from the data
--     directory listing; SHOW VARIABLES / STATUS / OPEN TABLES from server
--     memory. This is how MariaDB is built in general; it is NOT verified for
--     your exact build (the version is only known after this runs). Sections 3
--     and 11 record the mysql tables in the table cache before and after, as
--     evidence (not proof: other connections can change the cache).
--   * The information_schema privilege views list only accounts that have at
--     least one visible privilege row. They do NOT prove that an account name
--     is unused. The definitive name check is in 0A-2, and the 0B scripts will
--     use CREATE USER without IF NOT EXISTS, so an existing name makes them stop.
--
-- How to run: docs/phase0/0A_READONLY_INSPECTION.md (not phpMyAdmin).
-- =====================================================================

-- Safety net: this session refuses data changes from here on. (It does not
-- control anything the server does internally on its own.)
SET SESSION TRANSACTION READ ONLY;

SELECT '0A-1 / 1. Session' AS section;
SELECT CURRENT_USER() AS connected_as, NOW() AS server_time, UTC_TIMESTAMP() AS server_utc;
SHOW SESSION VARIABLES WHERE Variable_name IN ('tx_read_only', 'transaction_read_only');

SELECT '0A-1 / 2. Server settings (ACTIVE values reported by the running server)' AS section;
SHOW GLOBAL VARIABLES WHERE Variable_name IN (
  'version', 'version_comment', 'version_compile_os', 'version_compile_machine',
  'hostname', 'port', 'bind_address', 'skip_networking', 'basedir', 'datadir',
  'tmpdir', 'pid_file', 'log_error', 'log_basename', 'log_warnings', 'log_output',
  'general_log', 'slow_query_log', 'sql_mode', 'default_storage_engine',
  'character_set_server', 'collation_server', 'lower_case_table_names',
  'innodb_file_per_table', 'aria_recover_options', 'myisam_recover_options',
  'read_only', 'innodb_force_recovery', 'skip_grant_tables', 'table_open_cache');
SHOW GLOBAL STATUS WHERE Variable_name IN ('Uptime', 'Open_tables', 'Opened_tables',
                                           'Open_table_definitions', 'Aborted_connects');

SELECT '0A-1 / 3. mysql-schema tables in the table cache BEFORE the privilege queries' AS section;
SHOW OPEN TABLES FROM mysql;

SELECT '0A-1 / 4. Databases (names only)' AS section;
SELECT SCHEMA_NAME, DEFAULT_CHARACTER_SET_NAME, DEFAULT_COLLATION_NAME
FROM information_schema.SCHEMATA
ORDER BY SCHEMA_NAME;

SELECT '0A-1 / 5. Are the planned new database names free? (expect: no rows)' AS section;
SELECT SCHEMA_NAME
FROM information_schema.SCHEMATA
WHERE SCHEMA_NAME IN ('netcommand_lab', 'netcommand_test', 'netcommand_restore_check');

SELECT '0A-1 / 6. Grantees visible in the privilege views (may be incomplete; not proof of absence)' AS section;
SELECT GRANTEE, 'global'   AS level FROM information_schema.USER_PRIVILEGES
UNION SELECT GRANTEE, 'database' FROM information_schema.SCHEMA_PRIVILEGES
UNION SELECT GRANTEE, 'table'    FROM information_schema.TABLE_PRIVILEGES
UNION SELECT GRANTEE, 'column'   FROM information_schema.COLUMN_PRIVILEGES
ORDER BY GRANTEE, level;

SELECT '0A-1 / 7. Planned account names among visible grantees (expect: no rows; not proof of absence)' AS section;
SELECT DISTINCT GRANTEE FROM (
        SELECT GRANTEE FROM information_schema.USER_PRIVILEGES
  UNION SELECT GRANTEE FROM information_schema.SCHEMA_PRIVILEGES
  UNION SELECT GRANTEE FROM information_schema.TABLE_PRIVILEGES
  UNION SELECT GRANTEE FROM information_schema.COLUMN_PRIVILEGES) g
WHERE GRANTEE LIKE '''nc\_%';

SELECT '0A-1 / 8. Database-level privileges (in-memory copy of mysql.db; names only)' AS section;
SELECT GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE, IS_GRANTABLE
FROM information_schema.SCHEMA_PRIVILEGES
ORDER BY GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE;

SELECT '0A-1 / 9. Privileges of the existing NetCommand account (privilege names only)' AS section;
SELECT 'global' AS level, GRANTEE, '' AS object, PRIVILEGE_TYPE
  FROM information_schema.USER_PRIVILEGES   WHERE GRANTEE LIKE '''netcommand''@%'
UNION ALL
SELECT 'database', GRANTEE, TABLE_SCHEMA, PRIVILEGE_TYPE
  FROM information_schema.SCHEMA_PRIVILEGES WHERE GRANTEE LIKE '''netcommand''@%'
UNION ALL
SELECT 'table', GRANTEE, CONCAT(TABLE_SCHEMA, '.', TABLE_NAME), PRIVILEGE_TYPE
  FROM information_schema.TABLE_PRIVILEGES  WHERE GRANTEE LIKE '''netcommand''@%'
ORDER BY level, GRANTEE, object, PRIVILEGE_TYPE;

SELECT '0A-1 / 10. Global privilege summary per grantee (privilege names only)' AS section;
SELECT GRANTEE, GROUP_CONCAT(PRIVILEGE_TYPE ORDER BY PRIVILEGE_TYPE SEPARATOR ', ') AS global_privileges
FROM information_schema.USER_PRIVILEGES
GROUP BY GRANTEE
ORDER BY GRANTEE;

SELECT '0A-1 / 11. mysql-schema tables in the table cache AFTER the privilege queries' AS section;
SHOW OPEN TABLES FROM mysql;
SHOW GLOBAL STATUS WHERE Variable_name IN ('Open_tables', 'Opened_tables', 'Open_table_definitions');

SELECT '0A-1 / end' AS section;
