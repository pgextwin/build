\set ON_ERROR_STOP on
DO $$ BEGIN
IF current_setting('shared_preload_libraries') NOT LIKE '%pg_store_plans%'
THEN RAISE EXCEPTION 'pg_store_plans was not preloaded'; END IF;
END $$;
CREATE EXTENSION pg_store_plans;
SELECT pg_store_plans_reset();
CREATE TABLE public.pgextwin_plan_probe (i int NOT NULL);
INSERT INTO public.pgextwin_plan_probe SELECT generate_series(1,1000);
ANALYZE public.pgextwin_plan_probe;
SELECT count(*) FROM public.pgextwin_plan_probe WHERE i=17;
DO $$ DECLARE matches bigint; BEGIN
SELECT count(*) INTO matches FROM pg_store_plans
WHERE calls > 0 AND plan IS NOT NULL AND plan LIKE '%pgextwin_plan_probe%';
IF matches < 1 THEN RAISE EXCEPTION 'Executed SQL plan was not captured'; END IF;
END $$;
DROP TABLE public.pgextwin_plan_probe;
