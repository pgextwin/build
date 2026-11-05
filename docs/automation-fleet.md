# Central automation Fleet — operating contract

The single authoritative mutable Fleet is `pgextwin/build/metadata/automation-fleet.json` on protected `main`. At the 2026-11-05 source-bound read it registered **17 native extension repositories**. Membership, mode, strategy, schedule and release policy are data; the reusable workflow and executable code are SHA-pinned. Do not duplicate the Fleet as a second hand-maintained list. See [current architecture and onboarding](architecture.md), [Chat-first publication](chat-first-publication.md), and [Issue #510](https://github.com/pgextwin/build/issues/510).

## Nonpublishing candidate control

- `OFF`: no upstream discovery or candidate for that member.
- `WATCH`: stable upstream discovery and owned Issue reconciliation only.
- `BUILD`: additionally permits SHA-pinned draft candidate PR and nonpublishing Windows CI, **only** with local `config/candidate-build.json` exactly `{"schemaVersion":1,"enabled":true,"releasePolicy":"manual-only","workflow":"windows.yml"}`.

`scripts/fleet-control.py` validates unique repository identities, strategy equality, schedule/releasePolicy consistency, matching local upstream/watch fields and BUILD opt-in. Unknown, malformed, duplicate or inconsistent membership fails closed. A Fleet `releasePolicy` setting never substitutes for formal Publisher receipt, original signed source, App/Environment, separate policy or create-only tag.

The central `scheduleUtc` is `0 * * * *`. Each extension's actual `.github/workflows/update-watch.yml` schedule and genuine event chain must be inspected on its own protected `main`; for example, the existing `set_user` candidate caller uses `30 * * * *` and depends on a verified central scan. The legacy daily-only/14-extension statements predate the current Fleet. GitHub scheduling is not guaranteed wall-clock execution; Run and source proof are authoritative.

## Distinguish the four results

| Observation | What it establishes | What it does **not** establish |
| --- | --- | --- |
| `/pgextwin scan` on build#311 | Authenticated GET-only 17-member stable and public-tag observation | PR, signed source or permission to publish |
| Candidate draft PR and dispatched Windows CI | A pinned proposed update and observed supported-major unsigned Windows tests | Original PR Run SUCCESS, protected merge or formal Release |
| Original protected-main signing and independent Sigstore | A specific trusted, signed nonpublic source when all jobs succeed | A new Release without Publisher authorization |
| Independently verified formal Release + Catalog/Website | The respective completed public scope, after each real gate | Unrelated extensions, later upstream versions or unverified external ZIPs |

One authenticated Chat instruction may drive eligible actual updates through independent gates, but it cannot turn `action_required` or `SKIPPED` into SUCCESS. The original event type, actor and run attempt must remain exact. Existing published tags/assets are immutable and successful Runs are never repeated for extra evidence.

## Safe operation and onboarding

Use `schema/extension.schema.json`, `schema/update-watch.schema.json`, `schema/test-contract.schema.json`, `scripts/fleet-control.py`, `scripts/fleet-upstream-watch.py` and existing Windows callers. For an additional extension, first prove the existing regression fixture, then submit a narrowly scoped protected Fleet/adapter PR; require exact-head CI, postmerge and real functional proof before treating that slice of [#510](https://github.com/pgextwin/build/issues/510) as complete. Avoid bulk ref rewrites, new per-extension secrets, dummy releases, fake `schedule`/ `push` events, and disabled safety gates.

PostgreSQL support is resolved against `metadata/postgresql.json`; PG14 remains supported until **2026-11-12 UTC**. Historical public binaries remain visible after EOL, but a new default matrix must not silently include an EOL major.
