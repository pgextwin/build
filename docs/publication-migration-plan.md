# Review-only publication migration

This work prepares migration without changing deployed publication settings.
`publication-migration-plan.py` reads minimized GET records and prints JSON
review templates to stdout. It has no network, credentials, GitHub writes,
target-SHA binding option or apply mode. Every result declares
`publicationAuthorized=false`, `publishableReceipt=false`, `applyEnabled=false`
and `liveEvidenceVerified=false`.

The checked-in evidence is a historical authenticated GET snapshot of protected
build main `aecc5cde41b2478a09f4bbfc761ee3e650753fe4` and the 17 registered
extension mains on 2026-10-25. A second branch GET sweep matched their SHAs and
required checks. It contains 73 exact files: five central declarations plus
four files per extension. It contains no tokens, author emails or private keys.
Hashes detect corruption; they do not make a copied GET record authentic or
fresh. This preparation PR itself advances build main, so the historical bundle
must be refreshed before any future deployment PR.

```sh
python scripts/publication-migration-plan.py \
  --snapshot evidence/issue-75/publication-migration/extension-snapshot.json \
  --heads evidence/issue-75/publication-migration/observed-heads.json \
  > /tmp/pgextwin-publication-review.json
python tests/test-publication-migration-plan.py
```

`review-templates.json` is the reproducible output. It contains five central
policy diffs and two diffs for each registered extension: the local release
declaration and six supporting reusable-workflow pins (102 pins in this
snapshot). Membership comes from the snapshotted fleet, with no 17-member limit
in this planner. An added-member test verifies growth without a new branch or
per-extension implementation.

The attested builder stays at
`5756b3c5136a8bf4db710016cfe97555f0a71c6d`; detector cohort inputs, manifests and
candidate-only `manual-only` declarations stay byte-identical. All snapshotted
required checks are preserved, including plpgsql_check's eight checks, rather
than replacing them with one fleet-wide summary. Missing/duplicate members,
wrong App15368 requirements, changed protection, stale observed heads, bad Git
blob hashes, unknown or mutable workflow callers and altered signer pins are
rejected. Tests apply every generated diff inside temporary directories and
check the resulting central policy grammar and preserved files.

## Binding and application order

These are `.patch.in`-equivalent review templates, not apply-ready deployment
patches. Supporting workflow refs contain
`__APPROVED_PROTECTED_POLICY_SHA__`. The exact central merge SHA does not exist
until the future authorized protected PR is merged. A current code SHA whose
metadata still says manual cannot substitute for that policy snapshot. The
template blob hash is explicitly different from a future bound-file hash.

1. Finish genuine signed-candidate capability proof and effective authorization
   review for every declared control, including downstream prerequisites below.
   Static projections and scoped App canaries do not satisfy those conditions.
2. Re-GET the current protected heads, complete existing required checks and
   exact source files through authenticated GitHub GET. Regenerate and review
   if any source SHA, file or required-check set changed. Do not reuse this
   historical observation as fresh authority.
3. Only after authorization, propose the four Publisher declarations together
   with the fifth consistent Catalog downstream declaration in a normal
   protected central PR. Original-head required App15368 CI and genuine
   main/push postmerge must complete successfully. No protection changes.
4. Retrieve that actual protected merge SHA and exact five policy blobs. Verify
   code compatibility, the complete automatic policy bundle and original CI.
   Bind the supporting caller refs to that SHA, recompute final blob hashes,
   and review the materialized diff. A bare SHA or a placeholder replacement
   alone is insufficient. The planner intentionally cannot perform this step.
5. Create protected local declaration/caller PRs from fresh extension mains.
   Preserve signer pin, detector input, candidate policy, source manifest and
   every existing required check. Complete required CI and genuine postmerge.
   Recheck each head after merging. Intermediate repositories remain denied
   until all their own source and local-policy gates pass; there is no atomic
   cross-repository transaction.
6. Obtain a fresh original manifest-only signed candidate main/push on the new
   extension main and independently re-download ZIP/SPDX/Grype/Sigstore proof.
   **A policy/caller migration changes source main and invalidates proof bound
   to the previous main.** Existing `update-watch.yml` push paths select
   `config/extension.json`; a policy-only merge does not generate a valid
   manifest-only signing event. Await a genuine stable update rather than
   recycling an old Run, dispatching a substitute or manufacturing a version.
7. The actual original central schedule must establish independent source job,
   protected source/PR/App15368 checks, effective local/central policies,
   Sigstore, blocking Grype policy, scoped independent Publisher identity and
   absent tag/Release before create-only publication. Confirm actual token
   invalidation with HTTP401 and re-download the published bytes. A running
   workflow is not a successful completed Run.
8. Independently verify protected Catalog ingestion/merge, CLI retrieval and
   public Website rendering against that newly published Release. The public
   Publisher locator is an input to verification, never a receipt by itself.

No successful Windows fleet matrix, signature proof or App canary is rerun by
this planner. The application steps above are deliberately future steps whose
evidence must correspond to their actual new source heads.

## Downstream source audit and remaining work

This table records source inspection, not a new public Release E2E. Catalog
main was `e9e1bd9f09593686ee135135663c4e96e4194005`; Website main was
`88a642dc2d035514c686e2e44d232a6383ac49ec`. Runtime variables, credentials and
their effective opt-ins are not established by source GETs.

| Boundary | Existing connection | Remaining condition |
| --- | --- | --- |
| Automatic Release → Catalog verifier | [verify_signed_fleet_release.py](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/scripts/verify_signed_fleet_release.py) recognizes the public automatic locator; [automatic_publisher_provenance.py](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/scripts/automatic_publisher_provenance.py) independently GETs original source/main-push and distinct successful central schedule, App author and time order. Actual bytes and attestations are checked separately. | A genuine new public signed Release and completed Publisher Run; none supplied by these templates. |
| Catalog proposal | [sync-verified-release.yml](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/.github/workflows/sync-verified-release.yml) runs every six hours, verifies assets, then uses the existing proposer App only behind its opt-in. | Effective proposer opt-in and a new verified delta. No new App or Secret is proposed here. |
| Catalog protected merge | [auto_merge_verified_release.py](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/scripts/auto_merge_verified_release.py) already accepts separate manual and automatic downstream modes, plus local opt-in, original App15368 checks and public re-verification. | [local config](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/config/verified-release-auto-merge.json) is disabled. Central fifth declaration is disabled/pilot-only. Effective App/variable opt-ins and an actual eligible record PR remain unproved. First-Release index/landscape changes are outside the record-only auto-merge boundary. |
| Catalog → CLI | [cli-signed-catalog-feed.yml](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/.github/workflows/cli-signed-catalog-feed.yml) follows successful original protected-main Validate and attests the feed. [AuthenticatedCatalogHead.cs](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/dotnet/src/PgExtWin.Releases/AuthenticatedCatalogHead.cs) independently discovers protected Catalog main and downloads immutable records. | Feed and [SignedPublicCatalogFeed.cs](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/dotnet/src/PgExtWin.Releases/SignedPublicCatalogFeed.cs) require the historical PG14–18 set; the feed roster/workflow bounds are 14–17 identities. Future registered extensions and lifecycle-reduced major sets need coordinated trust-contract changes, not a blind removal of allowlists. Actual CLI retrieval of the new Release is still required. |
| Catalog → Website | [notify-website.yml](https://github.com/pgextwin/catalog/blob/e9e1bd9f09593686ee135135663c4e96e4194005/.github/workflows/notify-website.yml) invokes an immutable reusable public Pages audit after Catalog main push. Current Website reads Catalog main, hashes public pilot assets and cross-checks fleet Release digests. | Recheck compatibility of its pinned reusable revision; require actual public page/UI acceptance for the new Catalog entry. Existing source wiring is not a new deployment proof. |
| Future extension → scheduled candidate | The central planner and fleet policy grammar support registered growth. | `verify-scheduled-fleet-candidate.py` still has the historical 17-identity detector cohort boundary. Extending that independently audited boundary remains separate from generating migration diffs. The existing detector inputs are intentionally preserved here. |

The fifth-policy CI mismatch is fixed by this change: actual declarations use
the shared Catalog grammar, historical manual tests use frozen fixtures, and
the required future-policy copy runs all Python suites with all five proposed
declarations. No claim is made that the remaining Catalog/CLI/runtime boundaries
are already resolved. The four Publisher policies, fifth downstream policy and
all extension configs remain at their existing deployed values.
