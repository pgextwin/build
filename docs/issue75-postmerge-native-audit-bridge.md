# Issue #75 — verifying a native candidate after the protected main merge

Status: **pure deny-by-default postmerge binding only, nonpublishing**.
The owner has granted standing approval for **eligible** new stable Windows
Release versions without a separate human version-confirmation step. This
does not waive existing required CI, signed provenance, or create-only tags.

## Existing successful steps reused, not re-run

1. Native Windows PR PG14–18 produces immutable ZIP, SPDX and report-only
   Grype artifacts. The exact-head App15368 required Windows check succeeds.
2. `update-watch.yml` uses central pinned `verify-native-pr-candidate.yml`
   to re-download the **already built** binaries, check embedded packaging
   merge SHA, upstream full source SHA, content hashes and PG majors, and
   upload a named `candidate-audit-native-pr`. Real pg_ivm Run
   [39771145795](https://github.com/pgextwin/pg_ivm/actions/runs/39771145795)
   is the successful pilot; prior stale SHA failures remain rejected.
3. Central `bind-native-candidate-audit.py` and
   `bind-native-candidate-audit-live.py` (PRs #221/#222) independently bind
   the original GitHub PR, successful CI, audit Run, audit artifact ID,
   exact source manifest and five majors. Their outputs are nonpublishing.
4. This PR adds `automatic-postmerge-audit-bridge.py` as a **pure, read-only**
   bridge for the **subsequent** single manifest-only protected squash merge.
   It requires:
   - real existing-main GitHub push event with exactly one commit and approved
     operator identity (currently ShutenOishi, the known operator);
   - exact one-parent main commit and only config/extension.json changed;
   - closed/merged/same-repository bot-owned candidate PR, approved actor as
     merger, unmodified candidate ownership marker and Git blob identity;
   - actual protected main at the merge SHA, exact-head App15368 required
     summary SUCCESS and unique check;
   - prior **independently bound** successful CI + audit, original audit-main
     SHA exactly matching new squash merge parent (stale audits fail closed);
   - complete SHA-pinned source/maintained PG 14–18 matrix and ZIP digests,
     tied to the new protected-main source manifest.

## What this intentionally cannot do

Inputs to a pure function are not themselves authenticated. A production main
push runner MUST GET the original GitHub PR/commit/required checks/PR file
blobs and independently fetch the prior bound artifact with its exact ID;
until that runner exists, these tests are not an authenticated live acceptance
of a merged candidate. **No new event handler, token, App, Secret, privileged
workflow, Release policy, Signer, Publisher, tag, publication or Catalog write
is added by this PR.**

Every successful result has:
`status=MERGED_NATIVE_CANDIDATE_NONPUBLISHING`,
`signedArtifactsVerified=false`, `publishableReceipt=false`,
`publicationAuthorized=false` and `automaticReleaseEnabled=false`.
This output is NOT a `release-authorization.py` typed receipt, and the
existing manual-only Publisher must reject it.

## Subsequent steps

- Add the trusted protected-main push caller that independently downloads
  and authenticates all evidence (including exact audit artifact ID and
  effective bypass/branch protection, not merely the REST protected flag).
- Issue a new automatic-publication receipt **only after** source/version
  decision, candidate Windows matrix, signed attested fresh builder, actual
  Sigstore/SLSA/SPDX SHA256 asset verification, new tag uniqueness and
  publisher event authorization have independently passed.
- Preserve the existing fully functional manual workflow as rollback.
- After a single eligible real Release acceptance, deploy the thin common
  caller to 17/17 and independently verify Catalog, CLI and JA/EN Website.

Do not create or overwrite old Releases, downgrade CI, impersonate manual
PUBLISH, promote ordinary native PR zip metadata to signed evidence, or
claim an authorization policy enabled before it exists on protected main.
