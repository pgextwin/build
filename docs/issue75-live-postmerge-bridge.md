# Issue #75 — live protected-main postmerge witness, no publication

Status: **read-only GitHub event/REST/Artifact resolver; no Release permissions**.

The same signed Release safeguards that protect existing Windows binaries must remain mandatory before changing any production policy. In particular, a successful 17/17 native Windows CI or native `candidate-audit-native-pr` does not verify a signed Release or authorize a tag.

## Reused verified code

- `scripts/bind-native-candidate-audit.py` (central PR #221) validates exact source SHA and ZIP/SPDX/Grype digests.
- `scripts/bind-native-candidate-audit-live.py` (central PR #222) validates a real GitHub original native candidate audit artifact ZIP and original PR/Run provenance.
- `scripts/automatic-postmerge-audit-bridge.py` (central PR #223) matches a protected single-manifest candidate squash commit to the **prior** independently authenticated native audit, with exact base/main SHA and required App15368.
- All 17 repositories run the same SHA-pinned `verify-native-pr-candidate.yml`, with native audit accepted on pg_ivm Run 39771145795 and full real main/push postmerge PG14–18 85/85 SUCCESS.

## Additional logic in this PR

`scripts/automatic-postmerge-live.py` is a guarded read-only CLI for an eventual protected-main **push** Actions event. It fetches the real merged commit, associated bot PR, exact manifest blob at the new main SHA, branch protection/required check, and the previous main's completed GitHub `workflow_run` audit inventory. Only actual `candidate-audit-native-pr` ZIP files downloaded from one original GitHub Run are accepted. It matches these to the merged candidate PR head, verifies original Windows Run and source/ZIP hashes through the existing pure binder, and passes the fully bound observations to the existing protected merge bridge.

The command discovers Run/Artifact IDs itself from GitHub GET; no manually entered candidate run ID or publication key is needed. Paginated/ambiguous histories, stale base SHA, merged unrelated PR, multiple matching valid audits, wrong ZIP/attestation identity, old HEAD, wrong ref/actor and incomplete CI **fail closed**. Tests include real REST orchestration with controlled fixtures, rather than trusting untyped caller JSON.

### Unchanged security boundary

This PR only adds Python and required-resolver tests, no new local workflow trigger/secret/App/permission. Output `MERGED_NATIVE_CANDIDATE_NONPUBLISHING` **always** contains:
- `signedArtifactsVerified=false`
- `publishableReceipt=false`
- `publicationAuthorized=false`
- `automaticReleaseEnabled=false`

A production job must run the CLI on a **real** protected push from main using scoped read-only GitHub access and test its actual metadata. This library/test implementation does not demonstrate a live postmerge CLI run and cannot be substituted for a Publisher authorization receipt.

The next distinct stage is properly enabled **standing owner policy**, a true signed Windows build, independent cryptographic verification, typed automatic release receipt, create-only Publisher/tag and independent Catalog intake. Existing manual-only code remains functional and fail-closed until these gates exist.

Candidate pg_ivm v1.17 was successfully protected-merged as PR #28; its postmerge Windows Run must succeed before anyone calls the candidate accepted. The old signed Release remains untouched.
