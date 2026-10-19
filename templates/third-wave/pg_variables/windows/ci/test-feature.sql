\set ON_ERROR_STOP on
CREATE EXTENSION pg_variables;
DO $$ BEGIN
IF (SELECT extversion FROM pg_extension WHERE extname='pg_variables') <> '1.2'
THEN RAISE EXCEPTION 'Wrong extension SQL version'; END IF;
END $$;
SELECT pgv_set('pgextwin_session','value',101);
DO $$ BEGIN
IF pgv_get('pgextwin_session','value',NULL::int) <> 101
THEN RAISE EXCEPTION 'Set/get mismatch'; END IF;
END $$;
BEGIN;
SELECT pgv_set('pgextwin_session','value',202);
ROLLBACK;
DO $$ BEGIN
IF pgv_get('pgextwin_session','value',NULL::int) <> 202
THEN RAISE EXCEPTION 'Default nontransactional rollback incorrect'; END IF;
END $$;
BEGIN;
SELECT pgv_set('pgextwin_session','tx_value',101,true);
SAVEPOINT pgextwin_save;
SELECT pgv_set('pgextwin_session','tx_value',102,true);
ROLLBACK TO SAVEPOINT pgextwin_save;
COMMIT;
DO $$ BEGIN
IF pgv_get('pgextwin_session','tx_value',NULL::int) <> 101
THEN RAISE EXCEPTION 'Transactional savepoint rollback incorrect'; END IF;
END $$;
