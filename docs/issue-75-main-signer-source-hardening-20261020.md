# Issue #75 — main Signer checkout hardening staged, immutable Publisher pins unchanged

2026-10-20 JST. Source-only hardening of the central **future reusable Signer workflow**. This is NOT a live issued OIDC/Sigstore certificate test, Publisher upgrade, repin approval, candidate UPDATE or per-target PUBLISH.

## Fresh grounding and exact delta

The historical approved Signer is the immutable `pgextwin/build@5756b3c5136a8bf4db710016cfe97555f0a71c6d` with exact `build-extension-attested.yml` Git blob `93a0a7641253735cf5adb845c768981c79f75b46`. The original source is retained byte-for-byte as `tests/fixtures/issue-75-original-signer-5756b3c5.yml` so old trust-root/evidence/negative tests still evaluate that exact **historical** signer and do not pretend a current-main file was the old pinned source.

The **new main-source** `.github/workflows/build-extension-attested.yml` receives only the previous tested deterministic `scripts/issue-75-signer-checkout-hardening.py:hardened_signer` proposal: `persist-credentials: false` inserted in all **five** SHA-pinned `actions/checkout` steps (two Ubuntu matrix, three Windows build). All other workflow inputs, pinning, OIDC permissions, jobs and signing/SBOM steps remain byte-identical. `verify_main_candidate()` checks exact equality with the proposal and rejects any extra line, unexpectedly changed action, weakened credential setting or modified historical fixture, in required App15368 CI.

**No existing caller workflow is automatically migrated.** Independent current-main GETs of `pgtap`, `pg_variables`, `pg_store_plans` and `plpgsql_check` `.github/workflows/promote.yml` show their Signer calls still point at `@5756b3c5136a8bf4db710016cfe97555f0a71c6d`. The old pinned Signer remains as originally deployed and still has the five old credential-persistence gaps; changing main is not fixing its historic immutable commit. This PR deliberately does **not** edit the callers, release policy, central Publisher SHA, sign any package, run a privileged Signer, mint an OIDC token or issue a Release.

## Verification boundary

- New source allows future separately reviewed repin without reimplementing hardening from scratch.
- Required static suite confirms original immutable historical blob and exact new workflow source patch; this does not assert real runtime token absence. No actual attestation, Signed ZIP/SPDX/SLSA or positive prewrite is produced.
- The original GO A Run39008743613 FAILURE is retained, not waived; the old 45 Git Blob closure is unchanged as historical evidence.
- Before a future production Signer repin: independently approve exact source SHA, validate actual Windows signing workflow over supported majors, validate genuine Sigstore/X.509 OIDC issuer/SAN and run/attempt, original ZIP+SPDX bytes, transitive tooling trust and Viewer/Signer/Writer token isolation. Update each caller only via protected PR / required App15368 CI and separately satisfy actual user PUBLISH and independent Writer gates.

## Remaining verdict

**GO B/G4/G5 NO_GO; formal publication DENY; third-wave Release 0/3; actual Catalog 14/70; Publisher central allowlist 14, CLI v0.3.2 verbose preserved.** New main-source code is safer for a future controlled repin, but *Chat-only signed full Publisher* remains NOT_READY without separately approved private identity/custody and provenance verification.
