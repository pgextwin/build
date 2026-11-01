# AUTO v2.5 / R11 #484–#487 — protected nonpublishing transition control

The acceptance boundary is deliberately narrower than a finished schedule migration.
This PR adds a *real original-inventory-derived*, independently recalculated
read-only functional crosswalk, not a legacy Writer replacement or a cron deletion.

## Source and classifications

- #311 AUTO v2.5 is canonical; #75 is the related parent. #501 is **future-event reference only**.
- Reuse the existing protected-main 20-repository R11 inventory. The 17 extension
  `.github/workflows/update-watch.yml` files cover detection, Issue reconciliation,
  candidate PR, native CI, and signature reevaluation; hypopg has a second recovery cron.
- Build/catalog/website schedules are classified by authenticated workflow *path*
  into provisional function buckets. Unknowns are `UNCLASSIFIED_HOLD` rather than
  guessed acceptance. The original inventory retains cron and Git blob SHA.
- Every row explicitly says `replacementAccepted=false`,
  `writerFenceAccepted=false`, `recoveryAccepted=false`,
  `retirementAuthorized=false` until actual per-function proof is linked.
  The crosswalk is a *planning/verification input*, not an authorization token.

## Reused safety paths

- #484: exact mutable API resource keys classify shared operations as
  `SHARED_FENCE_REQUIRED`. GitHub Actions concurrency alone is not a CAS.
  A disjoint State branch path does not prove shared Issue/PR safety.
- #485: existing R06/App CAS + 409 and revoke401 originals remain canonical.
  The new bounded recovery contract cannot make a second PUT/POST:
  at most three authenticated GET observations; unknown/404/429/5xx
  exhaustion, 401/403, and stale conflicts quarantine. The pure test is
  **not** evidence of a naturally occurring provider outage.
- #486: original protected-main 20-repo scheduled-workflow inventory is the
  source for the replacement function map. The map is independently derived
  after real GET readback, retaining missing function-specific proof as pending.
- #487: this PR removes **zero** schedules. Each future removal requires
  a source/actor/HEAD/Run/ZIP/State/revision acceptance record for the
  exact target, legacy/new Writer protection, protected PR/required CI,
  original postmerge, and independent 20-repo GET.

## Regression and proof chain

The protected PR runs deterministic hostile checks for unknown resources, spoofed
repos, duplicate schedule entries, missing hypopg recovery cron, incomplete
20-repo inventory, stale/unknown ACKs, extra GETs, and any premature claim
of migration. The new postmerge R11 inventory workflow generates an original
JSON + functional crosswalk artifact, and the separate no-App-key runner
re-performs authenticated GET and checks exact output bytes.

Remaining work is **real** per-resource Writer fencing/hostile original,
bounded recovery integration, function-by-function substitution original,
then protected removal of proven-safe schedules only. No prior successful
Run is rerun. No PUBLISH authorization is granted. Runtime remains disabled.
