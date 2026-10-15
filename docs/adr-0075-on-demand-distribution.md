# ADR-0075-B: On-demand updates and one online/offline distribution contract

Status: **Proposed / no publication authorization**, 2026-10-15. Tracks [Issue #75](https://github.com/pgextwin/build/issues/75). This complements existing [manual release policy](step23-manual-queue.md) and [chat-authorization design](adr-0075-chat-authorized-publication.md); it does not override their current safe gates.

## Decision

Adopt **B: request-time update checks**; reject C (Actions Artifact zero). Use **GitHub Releases as canonical bytes/evidence**, and **Catalog v2 as canonical version, PG-compatibility and distribution records**. One generator projects verified Catalog records into a versioned offline manifest; a single CLI shares parsing, verification, compatibility and install planning between online and offline sources. Never make a second independent registry.

An upstream update request may create only stable SHA-pinned candidate Draft PRs and associated CI. A candidate is **not** a release instruction. Formal Release remains independent and requires all present source SHA, protected main, PG-major Windows CI, human manual PUBLISH, immutable signer and independent Publisher, SPDX, Grype report-only, true cryptographic attestation and fail-closed gates. Nothing here authorizes GO A, GO B, signer/Publisher repinning, automatic Release, tags, billing/Secret/App permissions or branch-protection changes.

## 1. Update B1 / fleet B2

Pilot `plpgsql_check` only. Remove `schedule` and `push` candidate-producing entrypoints from the pilot updater; leave other 13 unchanged until B1 acceptance. `workflow_dispatch` defaults to `dry_run=true`; it must inspect stable upstream without modifying Issues, opening candidate PRs, launching Windows candidate CI, or uploading `candidate-decision`. `dry_run=false` requires direct authorized human `ShutenOishi` actor and triggering_actor, `refs/heads/main`, attempt 1, the current main 40-character SHA and literal `UPDATE`. Fail closed on mismatch; separate least-privilege read-only and mutation-capable jobs. Use existing full SHA pinned central candidate implementation and deduplicate the pre-existing plpgsql_check 2.10.15 Draft.

Current Chat GitHub connector cannot start new `workflow_dispatch`. B1 is **a safe manual-dispatch pilot, not yet full one-Chat request UX**. A future Chat-triggered protected authorization PR must be threat-modeled, piloted and checked for authenticated operator provenance separately; never accept unauthenticated Issue comments as privileged commands. Require tested, current-head 8 App15368 contexts before a protected merge; preserve postmerge CI. `candidateEnabled` and the other 13 scheduled workflows are not globally disabled by this one Pilot. Central schedule metadata is updated only after fleet parity.

## 2. Shared distribution Manifest v1

Introduce a **snapshot envelope**, `pgextwin-distribution-manifest/v1`, as an explicitly versioned *projection* of immutable Catalog commit, not a substitute for Catalog v2 or PACKAGE-INFO.

Root fields: `schemaVersion`, `snapshotId`, `generatedAtUtc`, `catalogCommitSha` (40 hex), `catalogSchemaVersion`, `catalogIndexSha256`, `generatorVersion`, `selectionPolicy`.

Each `packages[]` row: `extension`, `pgMajor` (string; never hard-code PG14–18), `architecture`, **`packageVersion` for that PostgreSQL major**, `releaseTag`, `releaseId`, `sourceRepository` (including immutable numeric repo ID where available), `assetName`, `assetUrl`, `releaseAssetSha256`, `bundleRelativePath`, runtime/preload/background worker/client executables, PostgreSQL lifecycle/EOL, licensing and NOTICE fields. `pgaudit` and `pg_hint_plan` have PG-specific upstream versions; never infer those from the enclosing release tag.

Each `evidence` block: SPDX/Grype asset paths and SHA, attestation bundle name/hash, SLSA and SPDX predicate types, signer workflow and source ref, Sigstore trusted-root identity, verification tool/version/time, certificate source repository numeric ID, separately `evidencePresent` and `cryptographicallyVerified` with failure reason. SHA match alone is `INTEGRITY_ONLY`; no fabricated `SIGNATURE_VERIFIED`.

`coverage[]`: every expected extension × applicable PG major, states `included|unsupported|historical|missing|blocked`, with reason. Assemble the latest independently verified *published* stable asset **per PG major**, not every prior release. Historical packages require explicit lifecycle policy. If a required combination is missing/unverified, do not publish a bundle labeled COMPLETE and never substitute candidate Artifacts.

Archive layout (example; dynamic majors):

```
manifest.json
catalog/index.json
catalog/extensions/<extension>.json
packages/pg<major>/<extension>/<packageVersion>/<original-asset-name>.zip
evidence/<extension>/<releaseTag>/<asset>.spdx.json
evidence/<extension>/<releaseTag>/<asset>.vulnerabilities.json
evidence/<extension>/<releaseTag>/<asset>.attestations.jsonl
licenses/<extension>/LICENSE-or-NOTICE
cli/windows-x64/<self-contained-cli>
```

Copy **byte-identical per-extension ZIPs** (reverify original Release SHA). Independently authenticate the Catalog snapshot. Sign/attest the outer archive via a separately approved restricted bundler/publisher, create-only; never grant a build signer open-ended Release write. Include an independently distributed outer-archive digest/verification method so a tampered bundle cannot replace both its contents and its claimed hash.

## 3. One Windows CLI

Prefer self-contained C#/.NET x64; decide Native AOT after actual Windows compatibility tests. Commands: `list`, `search`, `download`, `verify`, `install --dry-run`, `install --apply`, with `--offline --bundle <path>`. Online adapter reads verified Catalog and official Release assets; offline adapter reads authenticated snapshot Manifest and original assets. Both feed one compatibility, verification and install-plan engine. Handle PG major, EOL, x64, installation path, file collisions, permission, preload, background worker, client EXEs. Default is dry-run; no implicit service restart, `shared_preload_libraries` edit, `CREATE EXTENSION`, DLL overwrite or privilege elevation. `--apply` requires distinct explicit authorization and safe staged/atomic behavior.

GitHub-supported offline cryptographic verification is `gh attestation download` + `gh attestation trusted-root` **while online**, then `gh attestation verify <asset> -R <owner>/<repo> --bundle <bundle.jsonl> --custom-trusted-root <trusted_root.jsonl> --signer-workflow ... --predicate-type ...` while offline. Check **numeric signing repository ID**, expected builder/source ref, OIDC issuer, predicate, subject hash and verification JSON. The trusted root, CLI signing identity and source manifest checksum must be authenticated **outside the untrusted bundle**; a root stored only inside the ZIP is not a trust anchor. Roots rotate, and stale roots cannot demonstrate current revocation state. Missing bundle, trust or validator = DENY, never silently reduce to SHA-only.

Required hostile tests: ZIP Slip/absolute/traversal paths, symlink tricks, duplicate entries, ZIP bomb/file limits, modified bytes/digest, forged Manifest, substituted otherwise-valid attacker signing repo/workflow, wrong predicate and root rotation, mismatched PG version/architecture, historical expiry, permissions/collisions/preload, offline-network denial and interruption/rollback.

## 4. Sequencing and blockers

P0 this ADR → P1 `plpgsql_check` nonpublishing B1 protected PR + hostile tests/CI/postmerge → P2 13-repo parity → P3 role-specific artifact retention (disposable Windows CI separate from candidate decisions, audits and promotion receipts/recovery) → P4 nonpublic bundle pilot from *existing* 14 public Releases → P5 common online/offline CLI pilot → P6 full request-to-Website/bundle/CLI acceptance. P4/P5 nonpublishing work may overlap P2/P3.

**Do not reduce organization/repository global retention to 1 day**: since 2026-10-01 it covers checks, runs, statuses and logs as well as Artifacts; retain critical evidence through immutable Issue/Catalog/Release records before shortening only disposable artifact `retention-days`. 500MB allowance and observed ~11.896MB/70 Windows Artifacts **do not establish current free headroom, $0 billing eligibility, or final invoice**. GitHub Support #4860203 remains pending. Publication DENY, GO A unsigned-canary 0/10, GO B/repin/G4/G5 NO-GO remain invariant.

References: [GitHub offline attestation verification](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline), [GitHub CLI verify](https://cli.github.com/manual/gh_attestation_verify), [retention scope](https://docs.github.com/en/organizations/managing-organization-settings/configuring-the-retention-period-for-github-actions-artifacts-and-logs-in-your-organization).
