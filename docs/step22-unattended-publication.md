# Step 22 — Unattended publication rollout and explicit safety boundary

## Objective

Operate the existing daily 00:00 UTC (09:00 JST) nine-extension upstream
watch without human intervention for **eligible, independently verified**
source updates, Windows candidate builds, formal signed Releases, Catalog
changes, and Website verification. The nine-repository fleet remains governed
by `metadata/automation-fleet.json`.

## Verified baseline (2026-10-09)

- All nine repositories are watched daily; eight are `WATCH` and
  `plpgsql_check` is the only `BUILD` pilot.
- The Step 19 candidate is a SHA-pinned manifest-only draft PR with a
  separately dispatched Windows matrix and `candidate-audit` artifact.
- Step 21 `promote.yml` requires a *separately reviewed* approval PR and
  manual `workflow_dispatch`; formal publication uses fresh signed
  artifacts and create-only/tag-reservation behavior.
- The Catalog dispatch creates a reviewable, **non-auto-merged** PR.
  Website publication verification runs every day and on main updates.
- The Step 21 GitHub App installation / secrets and Environment acceptance
  must be verified in the GitHub admin UI: do not infer that a secret exists
  from a referenced expression in YAML.
- The protected `plpgsql_check` main rejects merging PR #8 without an
  approval by someone other than the last pusher. Do not weaken all branch
  protections to evade this check.

## What this PR implements

The explicit default-deny `metadata/unattended-publication.json` contract,
the pure `scripts/unattended-policy.py` validator, and no-network
regression tests. `OBSERVE` is the sole deployed mode. No Release, App
credential, status check, PR approval, or mutable repository setting is
changed. This is **not** an unattended publisher.

The validator is only a *necessary static precondition*. Even an
`UNATTENDED` policy verdict explicitly returns
`automaticPublicationAuthorized: false`, because each publication must
still validate independent live evidence and credentials. Never consume this
JSON as an authorization receipt for `publish-release.py`.

## Implementation stages required before enabling any mutation

1. **GitHub identity and rules:** Confirm or install short-lived
   Actions-dispatch App identity for plpgsql_check → catalog → website;
   provision a separate minimal merge identity only where needed
   (Contents:write and Pull requests:write in the *target repository*).
   No PAT or long-lived token. Do not grant repo-wide Administrator.
   Examine main rulesets, most-recent-push approval requirement, required
   CI checks, no-force-push and no-delete controls; design a tightly
   constrained automation route rather than a universal bypass.
2. **Candidate auto-merge gate:** Act only on exactly one owned, immutable
   `auto-candidate/[hex]` PR with the expected marker; verify HEAD SHA,
   manifest-only diff, upstream signed/stable tag resolution, live central
   `BUILD` opt-in, and exact decision/watch identity. Require all maintained
   PG majors, successful Windows matrix, `candidate-audit.status=VERIFIED`,
   fresh security and source/license-change checks, nonexpired artifacts,
   and current main head. Never let PR-authored workflow code decide its own
   admission. Quarantine if any identity or API response is unknown.
3. **Independent vulnerability policy:** The current Grype report is
   **report-only**; a signed SBOM does not itself prove absence of exploitable
   vulnerabilities. Define reproducible critical/high thresholds, explicit
   allowlist expiration, scanner-DB freshness and license policy before
   automatic publication. Block on stale/unavailable vulnerability data.
4. **Formal automatic release:** Replace the *per-candidate human approval*
   with an independently authorized, machine-verifiable policy receipt.
   Keep manual Step 21 `promote.yml` for exceptional recovery. Reuse
   fresh, SHA-pinned trusted-main PG-major attested builds and the existing
   create-only release publisher; never resurrect the unsafe
   `release/*` branch path. A successful candidate matrix is insufficient.
   Prevent duplicate versions, tag reuse, concurrent promotions, and
   unverified partial drafts.
5. **Catalog automatic merge:** Validate the *public signed Release*
   independently in the Catalog repository (downloaded digest, attestation,
   `PACKAGE-INFO.json`, test contract pinned at the trusted commit,
   schema v2 and remote links). Merge only the generated, immutable,
   record-only `auto-catalog/` PR after its own required checks.
   Never automatically merge unrelated Dependabot or human PRs.
6. **Website and incident reconciliation:** Dispatch Pages acceptance
   with scoped GitHub App; require live ZIP/SHA/SBOM/Grype and UI checks;
   open/update a deduplicated incident and stop further promotions on
   failure. Distinguish queued, running, completed-success, stale and
   unavailable states; Github schedules are best effort.
7. **Expand deliberately:** Prove one real new-upstream end-to-end
   `plpgsql_check` publication and idempotent retries, then enable the
   other eight repositories one at a time. Respect per-PostgreSQL-major
   version strategies and lifecycle differences; never equate `WATCH`
   with consent to build or release.

## Safe acceptance matrix

| Case | Required result |
| --- | --- |
| No stable update | No-op; no Release/Catalog change |
| Duplicate run, repeated tag, tag collision | No new Release; quarantine |
| GitHub API outage or missing App secret | Deny, surface incident |
| Invalid/moved upstream tag or unknown license change | Deny |
| One Windows PG major fails or artifact is absent | Deny |
| Candidate audit mismatch or stale commit | Deny |
| Missing signed provenance or SBOM attestation | Deny |
| Vulnerability scanner missing or disallowed findings | Deny |
| Catalog tampered digest or partial ZIP set | Deny |
| Website public asset/UI audit fails | Incident and stop promotion |
| First verified upstream stable change | All checks pass; at most one immutable formal Release and a matching published Catalog/Website |

## Review commands

```bash
python scripts/unattended-policy.py \
  --policy metadata/unattended-publication.json \
  --fleet metadata/automation-fleet.json
python scripts/unattended-policy.py \
  --policy metadata/unattended-publication.json \
  --fleet metadata/automation-fleet.json --require-unattended
python tests/test-unattended-policy.py
```

The first command must report `OBSERVE_ONLY`; the second must **fail closed**
until the independent production implementation and one-time administrator
acceptance are complete.
