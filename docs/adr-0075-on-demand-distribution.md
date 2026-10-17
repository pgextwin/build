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

## 5. CLI-created offline ZIP product contract — owner clarification, 2026-10-17 (nonpublishing)

**This section controls the intended future distribution product.** It clarifies the older *proposed* archive/sign-and-publish language in sections 2–4 and [Issue #112](https://github.com/pgextwin/build/issues/112); do not interpret that language as authorization to publish new centrally prebuilt full-extension bundle ZIPs. The project owner requires a **client-side CLI that generates ZIPs in the user's own environment**. Existing immutable GitHub Release assets remain historical input/evidence, not newly authorized product bundles.

| Boundary | Required future behavior | Prohibited inference |
| --- | --- | --- |
| Online CLI | Retrieve the exact immutable Catalog snapshot and independently verified existing published Release bytes/evidence, apply major/architecture/runtime policy, then create the requested ZIP **locally**. A request may fetch source payloads, but must not publish a new ready-made bundle from CI. | A successful historical asset GET, unsigned Windows CI or GO A sign-only Artifact is **not** a new distributable Release/installation approval. |
| Offline preparation | In a networked environment, the CLI creates a transfer-ready ZIP from verified eligible inputs; transport it to a disconnected Windows host. No server-side pre-created new offline bundle is required. | A local ZIP's own embedded checksum or Catalog JSON is not an external signature of its origin. |
| Full-fleet portable ZIP | Generate **one ZIP for a selected PostgreSQL major** (e.g. `pgextwin-offline-pg18-windows-x64.zip`), containing eligible extension entries and the complete manifest/evidence/coverage snapshot for that major only; not one mixed-PG14–18 giant bundle. Explicitly label missing, blocked, unsupported and historical entries. | Do not advertise a 14/14 COMPLETE PG-major bundle while a required extension row lacks formally acceptable evidence. |
| Trust | Preserve original Release payload bytes and genuine SLSA/SPDX evidence, cryptographically verify before packing and again when using offline. Pin the Catalog commit and independent trust material. Distinguish verified provenance of **embedded source bytes** from cryptographic authorship of the **locally assembled archive**. | Do not call an unsigned locally generated archive a pgextwin-signed Release, and do not claim `SIGNATURE_VERIFIED` merely because its internal checksums match. |
| Installation | The same shared CLI parser/validator/planner handles online sources and a locally produced offline ZIP without network. `install --dry-run` comes before any separately gated `--apply` transaction; no hidden service restart, preload edit, SQL, privilege elevation, or overwriting. | A locally generated archive is not proof of successful install or safe write authorization. |

**Example client-local major-specific layout (schema names remain subject to P0 review):**

```text
pgextwin-offline-pg18-windows-x64.zip    # written by CLI on user's machine
  manifest.json                         # immutable Catalog commit + exact PG18 coverage
  catalog/index.json
  catalog/extensions/<extension>.json
  packages/pg18/<extension>/<version>/<original-release-asset>.zip
  evidence/<extension>/<release-tag>/<original-SLSA-SPDX-bundles>
  evidence/<extension>/<release-tag>/<SPDX-and-Grype-reports>
  licenses/<extension>/<license-or-notice>
```

**Trust bootstrap / negative boundary:** an offline target must have externally authenticated trusted-root/pinned signer identity and a trustworthy Catalog snapshot commitment, or fail closed. Material supplied only inside an attacker-replaceable ZIP cannot independently authenticate that ZIP. Preserve verified in-toto/Sigstore claims, actual Release asset IDs/SHA256 and source/packaging/run/attempt evidence; reject path traversal, duplicate members, symlinks, zip bombs, wrong PostgreSQL major/architecture, substitutions, stale roots and missing checks. Never claim online revocation freshness while disconnected.

**Fleet source acceptance is a separate prerequisite.** As of this clarification, the historical formal P1 ledger is **65/70**, the historical source ledger **40/40**, and `plpgsql_check` PG14–18 still has **five DENY** because the published Release's PUBLISH→publish-success causal bridge is not proven. The separate nonpublishing GO A Run 39008743613 generated and reverified 10 genuine signatures but its workflow concluded FAILURE; those Artifacts do not repair the historical P1 ledger and are not distributable inputs. No new Release/Tag/Publisher/GO B/G4/G5 is authorized.

**Revised nonpublishing sequence for Issue #112:**

1. **P0:** Inventory immutable Catalog, independently admissible historical Release/evidence and per-major availability; define deterministic manifest schema, client-generated PG-major ZIP identity, independent trust anchor and hostile fixtures. Explicit `blocked` coverage where P1 evidence is absent.
2. **P1:** Implement deterministic pure manifest generator and verifier on pinned fixtures. No publication workflow or signing privilege.
3. **P2:** Generate local/private prototype ZIPs on the CLI host for individual majors; byte-compare genuine eligible Release sources; deny incomplete or untrusted full-fleet claims. Do not upload a centrally assembled distribution ZIP.
4. **P3/P4:** Implement shared C#/.NET online/offline read/verify/pack and dry-run planner, then separately gated transactional install with rollback testing on disposable Windows systems.
5. **P5/P6:** Validate end-to-end local ZIP generation → offline transfer → independently trusted offline verify → dry-run/apply (when separately gated), Catalog/Website documentation and coverage. A new centrally signed/hosted bundle product is **outside** this clarification and would require a distinct product decision and security authorization.

**No change to current deployment/credential state.** The old Release assets, 14 manual-only promoters, candidate PRs, exact signer pin and source/PG lifecycle rules are preserved. This documentation amendment itself authorizes no new ZIP publication, Release/Tag, Actions Dispatch, signature, App/Secret, budget, branch protection or live installer write.
