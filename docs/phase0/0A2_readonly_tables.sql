-- =====================================================================
-- NetCommand Phase 0A-2: table inspection
--
-- DO NOT RUN THIS until the 0A-1 reports have been analysed and you have
-- approved 0A-2.
--
-- WHAT THIS SCRIPT SENDS
--   SELECT and SHOW statements, one PREPARE / EXECUTE / DEALLOCATE of a
--   generated SELECT (to count every table; run only after a completeness
--   check), user variables (@nc_..., this connection only), and two session
--   settings (read-only transactions; a longer GROUP_CONCAT limit for this
--   connection only).
--   There is no CREATE, ALTER, DROP, INSERT, UPDATE, DELETE, GRANT, REVOKE,
--   FLUSH, CHECK, REPAIR, ANALYZE, OPTIMIZE or SHOW GRANTS.
--
-- WHAT IT READS
--   Status of the mysql.* privilege tables; row counts of those tables; the
--   Db / User / Host columns of mysql.db; the User / Host columns of
--   mysql.user (no password or authentication column); the list and exact row
--   counts of every base table in the netcommand database.
--
-- WHAT IT WRITES
--   Nothing through its statements. The client's `tee` writes the report file.
--
-- WHAT IT CANNOT GUARANTEE: "READ-ONLY STATEMENTS" IS NOT "NO WRITE"
--   This script OPENS the mysql.* system tables (Aria engine) and every table
--   of the netcommand database. If an Aria or MyISAM table is marked as crashed
--   and the server's aria_recover_options / myisam_recover_options allow it,
--   merely opening that table can make the SERVER repair it automatically,
--   which writes to it. SET SESSION TRANSACTION READ ONLY does not stop the
--   server's own recovery. The 0A-1 results (recovery settings, error log) are
--   used to decide whether running this is reasonable.
--
-- If a statement fails, that failure IS the finding: send the report as is.
-- =====================================================================

SET SESSION TRANSACTION READ ONLY;
SET SESSION group_concat_max_len = 1000000;     -- this connection only

SELECT '0A-2 / 1. Session' AS section;
SELECT CURRENT_USER() AS connected_as, NOW() AS server_time;
SHOW SESSION VARIABLES WHERE Variable_name IN ('tx_read_only', 'transaction_read_only');
SHOW GLOBAL VARIABLES WHERE Variable_name IN ('version', 'aria_recover_options',
                                              'myisam_recover_options');

SELECT '0A-2 / 2. System table status (engine, rows, state comment)' AS section;
SELECT TABLE_NAME, TABLE_TYPE, ENGINE, ROW_FORMAT, TABLE_ROWS, DATA_LENGTH,
       CREATE_TIME, UPDATE_TIME, CHECK_TIME, TABLE_COMMENT
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'mysql'
  AND TABLE_NAME IN ('db', 'global_priv', 'user', 'tables_priv', 'columns_priv',
                     'procs_priv', 'proxies_priv', 'roles_mapping')
ORDER BY TABLE_NAME;

SELECT '0A-2 / 3. System tables can be read (one query per table; an error here is the finding)' AS section;
SELECT 'mysql.db'            AS table_name, COUNT(*) AS row_count FROM mysql.db;
SELECT 'mysql.global_priv'   AS table_name, COUNT(*) AS row_count FROM mysql.global_priv;
SELECT 'mysql.tables_priv'   AS table_name, COUNT(*) AS row_count FROM mysql.tables_priv;
SELECT 'mysql.columns_priv'  AS table_name, COUNT(*) AS row_count FROM mysql.columns_priv;
SELECT 'mysql.procs_priv'    AS table_name, COUNT(*) AS row_count FROM mysql.procs_priv;
SELECT 'mysql.proxies_priv'  AS table_name, COUNT(*) AS row_count FROM mysql.proxies_priv;
SELECT 'mysql.roles_mapping' AS table_name, COUNT(*) AS row_count FROM mysql.roles_mapping;

SELECT '0A-2 / 4. mysql.db entries (names only, no privilege columns)' AS section;
SELECT Db, User, Host FROM mysql.db ORDER BY Db, User, Host;

SELECT '0A-2 / 5. Accounts (User and Host only, no password or authentication columns)' AS section;
SELECT User, Host FROM mysql.user ORDER BY User, Host;

SELECT '0A-2 / 6. Are the planned account names free? (definitive check; expect: no rows)' AS section;
SELECT User, Host FROM mysql.user
WHERE User IN ('nc_lab_api', 'nc_lab_migrate', 'nc_test')
ORDER BY User, Host;

SELECT '0A-2 / 7. Everything in the netcommand database (the "before" record)' AS section;
SELECT TABLE_NAME, TABLE_TYPE, ENGINE, TABLE_ROWS AS approx_rows, DATA_LENGTH,
       INDEX_LENGTH, CREATE_TIME, UPDATE_TIME, TABLE_COLLATION
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'netcommand'
ORDER BY TABLE_NAME;

SELECT '0A-2 / 8. Number of base tables in netcommand (must equal the number of rows in section 9)' AS section;
SELECT COUNT(*) AS base_tables
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'netcommand' AND TABLE_TYPE = 'BASE TABLE';

SELECT '0A-2 / 9. Exact row count of EVERY base table in netcommand (generated from the same list)' AS section;
-- One SELECT COUNT(*) per base table, joined with UNION ALL, built from the
-- same information_schema list as sections 7 and 8, so the two always agree.
-- Views (if any) are listed in section 7 but not counted (they hold no rows).
--
-- Truncation safeguard: GROUP_CONCAT silently cuts its result at
-- group_concat_max_len (with only a warning). So the exact expected length is
-- computed separately (sum of all pieces + separators) and compared with the
-- generated text. Only a COMPLETE query is prepared and executed; otherwise a
-- FINDING row is shown and NO counts are produced, so partial counts can never
-- be mistaken for complete ones.

-- 9a. Expected number of pieces and exact expected length (no GROUP_CONCAT involved)
SELECT COUNT(*),
       IFNULL(SUM(CHAR_LENGTH(CONCAT('SELECT ', QUOTE(TABLE_NAME), ' AS table_name, COUNT(*) AS exact_rows ',
                                     'FROM `netcommand`.`', REPLACE(TABLE_NAME, '`', '``'), '`'))), 0)
         + GREATEST(COUNT(*) - 1, 0) * CHAR_LENGTH(' UNION ALL ')
  INTO @nc_tables, @nc_expected_len
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'netcommand' AND TABLE_TYPE = 'BASE TABLE';

-- 9b. The generated query (NULL when there are no base tables)
SELECT GROUP_CONCAT(
         CONCAT('SELECT ', QUOTE(TABLE_NAME), ' AS table_name, COUNT(*) AS exact_rows ',
                'FROM `netcommand`.`', REPLACE(TABLE_NAME, '`', '``'), '`')
         ORDER BY TABLE_NAME SEPARATOR ' UNION ALL ')
  INTO @nc_count_sql
FROM information_schema.TABLES
WHERE TABLE_SCHEMA = 'netcommand' AND TABLE_TYPE = 'BASE TABLE';
SHOW WARNINGS;   -- a truncation warning (code 1260) would be listed here

-- 9c. Completeness check (shown in the report)
SELECT @nc_tables AS base_tables,
       @nc_expected_len AS expected_length,
       CHAR_LENGTH(@nc_count_sql) AS generated_length,
       @@SESSION.group_concat_max_len AS group_concat_max_len,
       CASE
         WHEN @nc_tables = 0 THEN 'NO BASE TABLES'
         WHEN @nc_count_sql IS NOT NULL AND CHAR_LENGTH(@nc_count_sql) = @nc_expected_len THEN 'COMPLETE'
         ELSE 'FINDING: generated query is INCOMPLETE (truncated); counts were NOT run'
       END AS check_result;

-- 9d. Run the counts only when the query is complete
SET @nc_run_sql = CASE
  WHEN @nc_tables = 0 THEN
    'SELECT ''(no base tables found in netcommand)'' AS table_name, NULL AS exact_rows'
  WHEN @nc_count_sql IS NOT NULL AND CHAR_LENGTH(@nc_count_sql) = @nc_expected_len THEN
    @nc_count_sql
  ELSE
    'SELECT ''FINDING: count query incomplete (GROUP_CONCAT truncated); NO counts produced. Report this; do not treat any count as complete.'' AS table_name, NULL AS exact_rows'
END;

SELECT @nc_run_sql AS statement_to_run;
PREPARE nc_counts FROM @nc_run_sql;
EXECUTE nc_counts;
DEALLOCATE PREPARE nc_counts;

SELECT '0A-2 / end' AS section;
