# Issue #75 — Phase D read-only GitHub evidence adapter

Status: **IMPLEMENTED LIBRARY + OFFLINE SECURITY TESTS; NO LIVE PUBLICATION ACCEPTANCE**  
Tracking: https://github.com/pgextwin/build/issues/75

## Purpose and trust boundary

The Phase C pilot [real main Run 38397010940](https://github.com/pgextwin/plpgsql_check/actions/runs/38397010940)
proved an exact-main read-only Classic REST + effective-rule GraphQL composite with
a dedicated Administration:read GitHub App. Phase D [Build PR #87](https://github.com/pgextwin/build/pull/87)
added an *inert* double-read identity/TOCTOU contract using synthetic evidence.

`scripts/chat-pr-phase-d-github-readonly.py` now implements a narrowly
repository-bound real-data adapter, without a CLI entrypoint or any installed
Actions workflow. It is a **library** for a future separately reviewed trusted
main-only job. It must not be imported/executed from a PR-supplied checkout,
and no untrusted event/body/receipt is a source of authority.

## What the adapter checks when invoked in a trusted future runtime

- Separates the **existing dedicated read-only Administration App token**
  (real single-repository Installation scope and same-token double REST/GraphQL
  Classic policy proof) from a repository-scoped **read-only evidence token**
  (GitHub PR/commits, check runs, contents, Actions metadata). No broadening of
  the dedicated App installation/permissions is required or permitted.
- Uses strictly allowlisted GET paths, bounded JSON, duplicate-key denial,
  pagination denial, no redirected authenticated reads, and 404-as-absent only
  for the two exact tag/Release lookup endpoints.
- Re-reads current protected main, exact one-file authorization squash commit,
  unique merged authorization PR, immutable committed JSON blob SHA, exact
  operator/event/parent, GitHub Actions check runs at *the PR head* bound to
  all eight required trusted App contexts, and currently empty tag + Release.
- Re-runs the previously audited read-only Classic composite with its own two
  main-SHA-bound REST/GraphQL snapshots, including PR bypass zero and push
  allowances zero. Missing/inconsistent/falsified policy denies.
- Reads the actual candidate PR, candidate Windows and decision run metadata,
  exact frozen extension/local manifest from Git blobs, and installed central
  build policies. It will **DENY while the real central/local policy is
  `manual-dispatch`**, as it currently is. The tests never edit these policies.
- Has a separate read-only Windows artifact path: `gh run download` retrieves
  candidate-decision, candidate-audit, ZIP, SPDX and Grype files. Each ZIP is
  independently rehashed and compared with the candidate audit; PACKAGE-INFO
  PG/source/run fields, SPDX 2.3 and Grype report structure are revalidated.
  Real `gh attestation verify` **twice per ZIP** must confirm the trusted
  `pgextwin/build/.github/workflows/build-extension-attested.yml` signer
  and the signed SPDX predicate. A green Windows CI or an audit-supplied
  SHA256 is **not** a substitute for signed assets. An ordinary unsigned
  candidate ZIP will DENY, not count as an attested Release.
- Re-runs the existing `fleet-promotion-gate.verify` and exact candidate/PR
  identity join; captures two independently fetched rounds and additionally
  requires identical authenticated ZIP digests on both rounds.
- The existing Phase D coordinator **always returns**
  `DRY_RUN_PHASE_D_RECHECK_ONLY`, `publishableReceipt=false`,
  `publishingEnabled=false`, `signedArtifactsVerified=false`.
  Independent candidate byte/signer checks here do **not** attest the future
  signed Release builder or convert this library into publisher authorization.

## CI and limits

`tests/test-chat-pr-phase-d-github-readonly.py` exercises hostile path/URL
attempts, accidental write requests, missing/invalid/duplicate/oversized
JSON, pagination, 404 confusion, committed Git blob SHA tampering, unsigned
ZIP, changed SHA256, wrong PACKAGE-INFO/source and SPDX, invalid matrix,
positive **mock** dual attestation, and no real authorization. All network
and GitHub CLI operations are mocked. The normal protected build `resolver`
runs these alongside the existing Phase C and D negative fixtures.

**No live PUBLISH authorization PR exists, and the current candidate is not
an accepted signed Release.** An adapter test with synthetic data is not
a live end-to-end proof. In particular, a future read-only runner must still
bind `event` to GitHub's trusted main push environment, pin the build checkout,
set minimal read-only evidence permissions, and handle any credential/read
failure as DENY. Issuing a publication-capable receipt or creating a release
would require additional separately reviewed policies, signature verification
at the Release boundary, atomic create-only tag handling, concurrency/replay
guarding and a user's explicit PUBLISH instruction.

Unchanged: all `manual-dispatch` production policies and workflows,
GitHub App/secret/branch settings, tag/Release history and catalog publisher.
Issue #75 stays OPEN until real eligible publication acceptance.
