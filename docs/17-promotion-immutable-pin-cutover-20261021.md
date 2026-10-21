# Release Promotion immutable caller cutover contract (2026-10-21)

This is a **source-only, nonpublishing** reconciliation. It is not a signer/
Publisher attestation, human PUBLISH authorization, or a new release instruction.

## Evidence which has actually been verified

1. The 13 original local `promote.yml` sources were all identical after
   normalizing their own extension names (one inert 143-line reference; exact
   per-repository Git blob SHA recorded in
   [promotion-legacy-parity-20261021.json](../metadata/promotion-legacy-parity-20261021.json)).
2. The previously deployed shared caller pins for the four remaining repos are
   **two different commits of central build**:
   - `plpgsql_check`: `5425225ea858f8c0165421902c3e66c6c9205f60`
   - Wave3 three: `acd6eb28be6d750e89b626fa4ccd4403e1265cd6`
   The actual shared workflow source files fetched from those Git refs have
   identical Git **blob** SHA `1a87339fdf93d093aea0c976d7627ce9d8860eb1`;
   that source is kept solely as an inert `.txt` test fixture.
3. Both historical shared versions still check out the earlier gate/Publisher
   commit `455f0ccc667697f600700a6e64bcfd6c57b6a977`. The **proposed**
   source-only 17-caller central Workflow checks out the distinct future gate/
   Publisher source `dd4d35186edccfbf39b40d86cecb28380cf210da`;
   it also adds an explicit Catalog dispatch flag beyond historical
   client-ID-only behavior. These differences must be validated separately.
4. The historical signed builder pin is `5756b3c5136a8bf4db710016cfe97555f0a71c6d`.
   Old live Signer OIDC/X.509 original ZIP, SPDX, SLSA run/attempt provenance
   has **not** been independently accepted for the three new Releases. The
   central source-hardening changes do not rewrite immutable history.
5. The original 14 production publisher allowlist and local flags are unchanged.
   All three Wave3 local `config/release-promotion.json` policies remain
   `enabled=false`; signed formal Releases are 0/3, PUBLISH DENY,
   GO B/G4/G5 NO_GO. Catalog has 14 records.

## Non-negotiable cutover sequence

1. Obtain the existing auditor App 5295410/installation170837728 authenticated
   Administration:read **real**, target-scoped proof from an approved isolated
   executor. Same-main-SHA REST/GraphQL + Rulesets double snapshot and positive
   token revocation; an owner GUI configuration screenshot is not token proof.
2. Accept independently signed signer source/runtime original bytes,
   ZIP/SPDX/SLSA and Sigstore OIDC run and attempt; target-specific Writer and
   Publisher short-lived isolated credentials and create-only prewrite/recovery.
   A synthetic/fixture test never equals actual signature verification.
3. Compare the two *different* pinned gate/Publisher implementations with
   negative/adversarial and actual nonpublishing runtime evidence before any
   production caller repin; retain the manual PUBLISH boundary and optional
   catalog dispatch authorization.
4. Only then may each of the 13 legacy caller migrations proceed by separate
   protected PR with exact-head required App15368 CI and real main/push
   postmerge. The existing shared four also require independently justified
   immutable repins, even when old workflow blobs happen to be equal.
5. The three first formal Wave3 promotions additionally require separately
   authorized per-target human PUBLISH, all current GO gates positive and
   successful real signed Release, exact original public asset bytes/hash and
   provenance. Catalog is updated only by its signed-release verifier's
   independently checked protected PR, then CLI and EN/JA Website verification.

**Blocked is not complete:** The GitHub connector cannot GET
`/branches/main/protection` (HTTP 403) and has no independent App JWT/key in
an approved isolated runtime. Do not add secrets to CI or treat signed binaries,
permissions, branch rules or Release acceptance as proven by this document.
