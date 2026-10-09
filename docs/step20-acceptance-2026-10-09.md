# Step 20 fleet automation acceptance — 2026-10-09 (JST)

## Decision

**PASS for presently testable Step 20 controls and no-update operation; real-new-release candidate E2E remains NOT_TESTED.**
Do not equate a no-op run or a mocked proposer test with proof that an actual upstream update triggers an end-to-end candidate.

- Nine extension watch runs complete with `success` and **one `candidate-decision` artifact each** after SHA-pinned rollout.
- `plpgsql_check`: central BUILD with local opt-in; actual non-dry-run plan reports `status: no-op`, `updates: []`, and proposer skipped; current stable upstream `v2.10.13`.
- Other eight: central WATCH, local candidate disabled; candidate decision explicitly `status: centrally-suppressed`, `mode: WATCH`, `updates: []`; proposer skipped.
- All nine rollout PR Windows regression CI runs completed successfully, across each repository's maintained PG majors.
- Required daily cron remains `0 0 * * *` UTC (target 09:00 JST). Actions scheduling is not guaranteed to start at the exact minute.
- Formal publication remains **manual-only**. No Step 20 Release, Catalog or Website mutations.

## Per-extension evidence

| Extension | Mode | Dry-run watch | PR regression Windows CI | Post-merge main watch (candidate-decision artifact) |
| --- | --- | --- | --- | --- |
| [plpgsql_check](https://github.com/pgextwin/plpgsql_check) | BUILD | [PASS](https://github.com/pgextwin/plpgsql_check/actions/runs/37896025204) | [PASS](https://github.com/pgextwin/plpgsql_check/actions/runs/37905689478) | [PASS + artifact](https://github.com/pgextwin/plpgsql_check/actions/runs/37906983654) |
| [pg_bigm](https://github.com/pgextwin/pg_bigm) | WATCH | [PASS](https://github.com/pgextwin/pg_bigm/actions/runs/37896069738) | [PASS](https://github.com/pgextwin/pg_bigm/actions/runs/37905695417) | [PASS + artifact](https://github.com/pgextwin/pg_bigm/actions/runs/37907069351) |
| [pg_cron](https://github.com/pgextwin/pg_cron) | WATCH | [PASS](https://github.com/pgextwin/pg_cron/actions/runs/37896102530) | [PASS](https://github.com/pgextwin/pg_cron/actions/runs/37905751113) | [PASS + artifact](https://github.com/pgextwin/pg_cron/actions/runs/37907125869) |
| [pg_hint_plan](https://github.com/pgextwin/pg_hint_plan) | WATCH | [PASS](https://github.com/pgextwin/pg_hint_plan/actions/runs/37896132610) | [PASS](https://github.com/pgextwin/pg_hint_plan/actions/runs/37905756625) | [PASS + artifact](https://github.com/pgextwin/pg_hint_plan/actions/runs/37907172213) |
| [pgaudit](https://github.com/pgextwin/pgaudit) | WATCH | [PASS](https://github.com/pgextwin/pgaudit/actions/runs/37896158056) | [PASS](https://github.com/pgextwin/pgaudit/actions/runs/37905825280) | [PASS + artifact](https://github.com/pgextwin/pgaudit/actions/runs/37908423301) |
| [pg_repack](https://github.com/pgextwin/pg_repack) | WATCH | [PASS](https://github.com/pgextwin/pg_repack/actions/runs/37896184760) | [PASS](https://github.com/pgextwin/pg_repack/actions/runs/37905819523) | [PASS + artifact](https://github.com/pgextwin/pg_repack/actions/runs/37908437037) |
| [pg_ivm](https://github.com/pgextwin/pg_ivm) | WATCH | [PASS](https://github.com/pgextwin/pg_ivm/actions/runs/37896212357) | [PASS](https://github.com/pgextwin/pg_ivm/actions/runs/37905899191) | [PASS + artifact](https://github.com/pgextwin/pg_ivm/actions/runs/37908494529) |
| [pg_qualstats](https://github.com/pgextwin/pg_qualstats) | WATCH | [PASS](https://github.com/pgextwin/pg_qualstats/actions/runs/37896239844) | [PASS](https://github.com/pgextwin/pg_qualstats/actions/runs/37905912420) | [PASS + artifact](https://github.com/pgextwin/pg_qualstats/actions/runs/37908711007) |
| [set_user](https://github.com/pgextwin/set_user) | WATCH | [PASS](https://github.com/pgextwin/set_user/actions/runs/37896265150) | [PASS](https://github.com/pgextwin/set_user/actions/runs/37905905077) | [PASS + artifact](https://github.com/pgextwin/set_user/actions/runs/37908508387) |

Every post-merge main watch produced exactly one `candidate-decision` Actions artifact. The eight WATCH artifacts are intentional suppression decisions, not evidence of proposed upstream updates.

## Shared Build change and test evidence

- [Build PR #36](https://github.com/pgextwin/build/pull/36) (merged, commit `16b886b9d06d6f389b369b87ce0c155767697ca0`): WATCH/OFF decisions are recorded and uploaded; this immutable SHA is pinned by all nine extension watcher and candidate-auditor workflows.
- [Build PR #37](https://github.com/pgextwin/build/pull/37): isolated fixtures for duplicate/human-owned candidate PR refusal, already-dispatched CI suppression, closed PR non-reopening, and central API failure failing closed; [CI success](https://github.com/pgextwin/build/actions/runs/37906301801).
- [Build PR #38](https://github.com/pgextwin/build/pull/38): isolated simulated successful SHA pin -> candidate branch -> draft PR -> one Windows workflow dispatch; [CI success](https://github.com/pgextwin/build/actions/runs/37909295204), [post-merge main CI success](https://github.com/pgextwin/build/actions/runs/37909416165). Simulation performs no network mutations.
- PG-major series fixture covers a PG15-only upstream update without changing PG16, and rejects informational PG19 from production candidacy. This is fixture verification, not live series-release acceptance.
- The [fleet-status run](https://github.com/pgextwin/build/actions/runs/37896518219) previously succeeded; its snapshot was collected **before** the rollout's nine new candidate-decision artifacts, so rely on the post-merge run links above for final artifact acceptance.

## Publication invariant

- The nine Extension GitHub Release latest publication dates remain Oct 5–8, 2026; no new Step 20 Release.
- Catalog `main` remains `6967ebac417094ca2331c4961bc57a11082bf339`.
- Website `main` remains `56695073c5d02c101a17883c6a98369389393e1d`.
- All nine repositories have no open `auto-candidate/*` pull request as of final audit.

## Deferred production E2E gate

A genuinely newer stable upstream version is required to verify production candidate PR creation, actual immutable upstream source checkout, auto-dispatched Windows major matrix, ZIP/SPDX/Grype evidence, and candidate-audit results together. None was detected on 2026-10-09. Do not invent a release or downgrade `main` to force an artificial candidate.

**Until a real successful E2E occurs, keep `plpgsql_check` as the sole BUILD pilot and the remaining eight on WATCH.** Treat a future real candidate as a separate audited acceptance gate before widening BUILD, and keep Release publication manual-only.

## Change control

This file is an auditable acceptance record. It does not activate any additional candidate build, publish a Release, or alter Catalog/Website.
