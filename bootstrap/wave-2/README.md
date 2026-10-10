# Wave 2 packaging repositories — staging workspace

Each child folder is intended to become the root of a separate pgextwin extension repository. **Do not mark any staged extension as implemented.**

Priority: 1. HypoPG, 2. wal2json (PG18 hard-gated), 3. pg_partman, 4. pg_stat_monitor, 5. orafce.

Organization repository creation requires the GitHub web UI; the connected code API can edit existing repositories only. After bootstrap, Windows CI must pass PG15–18 before any official releases, Catalog changes or Website publication.
