\set ON_ERROR_STOP on
CREATE EXTENSION pgtap;
DO $$ BEGIN
IF (SELECT extversion FROM pg_extension WHERE extname='pgtap') <> '1.3.4'
THEN RAISE EXCEPTION 'Incorrect pgTAP version'; END IF;
END $$;
SELECT plan(2);
SELECT ok(true,'pgextwin positive');
SELECT ok(false,'pgextwin intentional failure');
SELECT * FROM finish();
