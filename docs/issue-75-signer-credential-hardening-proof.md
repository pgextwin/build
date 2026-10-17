# Issue #75 — Signer checkout credential remediation candidate / Action dependency roots

2026-10-17. **Source-only inert hardening, no active signer change; GO B/G4/G5 NO-GO.** This complements, and does not overwrite, the existing [45 Git Blob / 54 edge / 16 external dependency record](../evidence/issue-75/transitive-dependency-delta-20261017.json).

## Five active Signer checkouts and mitigation

The actually deployed signer remains the immutable `pgextwin/build@5756b3c5136a8bf4db710016cfe97555f0a71c6d` reusable workflow, with exact workflow Git Blob `93a0a7641253735cf5adb845c768981c79f75b46`. It has **five** `actions/checkout` invocations: 2 in matrix and 3 in Windows build. None sets `persist-credentials:false`. The pinned `actions/checkout` root manifest itself describes writing the default GitHub token to local Git configuration when persisted and removing it at post-job cleanup. The scope is the Signer job token (contents read plus OIDC/attestation-related permissions), **not** the Publisher Writer token; this does not prove a real cross-job leak.

[Inert proposal generator](../scripts/issue-75-signer-checkout-hardening.py) rejects any signer Blob change, alternate checkout Action SHA, fewer/more checkouts, already-overridden credential fields, mismatched Action evidence, and false GO B authorization. It produces **only** a deterministic *proposed* Git Blob ID after adding `persist-credentials: false` to all 5 checkout steps in memory. It writes **no workflow** and changes neither actual Signer SHA nor pilot `promote.yml`. A later source-change PR, new immutable Signer SHA, reference/caller binding review, full CI, signed tests and explicit release safety-gate decision would be needed for real deployment.

## Six Action immutable root GETs

[Action evidence](../evidence/issue-75/action-roots-signer-hardening-20261017.json) records the original SHA-pinned checkout, setup-python, upload-artifact, download-artifact, attest and create-github-app-token source commits and **each** exact Git Blob SHA of `action.yml` and `package-lock.json`, plus the Git Tree SHA of `dist`. These 18 new Git object references are based on GitHub public immutable root tree and manifest GETs. This is **not** a verified runtime JavaScript bundle or Node/npm dependency closure; a Git Tree SHA is **not** a downloaded ZIP SHA256 or an attestation.

`setup-python` has a Python version selector `3.13`, not a patch-exact Python binary digest. The Signer's two `python -m pip install jsonschema>=4,<5` calls are floating. The pilot `meson==1.8.3` and `ninja==1.11.1.4` pin versions only, not wheel SHA256. PostgreSQL Chocolatey PG14–18 metadata identifies package names and versions but not package archive/content SHA256. Signer Syft/Grype ZIP SHA256 are in their installer source; downloaded bytes were **not** re-verified in this job. `windows-latest` / `ubuntu-latest` runner image labels, toolchains and Grype DB are mutable.

## Disposable PR-only isolation experiment

Added `issue75_sandbox_probe` in existing build `validate.yml`, strictly limited to branch `issue-75-signer-credential-external-proof` and `pull_request`, with job permission **`contents:read` only**, no explicitly exposed token, no Secret, no upload/download Artifact, no gh/GitHub write API, no Signer, no Publisher. A matrix runs on **ubuntu-latest** and **windows-latest**. Each separately checks out the disposable PR with `persist-credentials:false`, then the sandbox script examines local `.git/config` and nested Git credentials without printing data. It reports OS/image/Python/Chocolatey-cli **versions** as runtime inventories, not reproducible image or binary digests. Synthetic credentials in Git config are rejected by the separate hostile offline tests.

Even a successful PR-only sandbox run proves only **its own local checkout** did not expose recognized credential patterns. It is **not** direct observation of the old pinned Signer checkout, the real Reader token scopes, or a Writer token boundary. A failure is `SANDBOX_NOT_PROVEN`, never a GO B approval. All older independent GET-only observation, schema v2 `UNKNOWN_QUARANTINE` classification, failed GO A and successful unsigned candidate proofs are reused unchanged.

## Invariant

Actual Publisher `455f0ccc667697f600700a6e64bcfd6c57b6a977` and Signer SHA `5756b3c5136a8bf4db710016cfe97555f0a71c6d`, `promote.yml`, Secret, budget, branch protection and Release triggers are unchanged. Candidate PR #29 remains DRAFT; no Run dispatch or publishing operation was added. Formal P1 **65/70**, independent source **40/40**, plpgsql_check PG14–18 **five DENY**, P1 BLOCKED/P2 NO-GO, GO B/G4/G5 NO-GO, formal Release/distribution DENY.
