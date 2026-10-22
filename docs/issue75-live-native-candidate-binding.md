# Issue #75 — real GitHub native candidate audit binding (nonpublishing)

The shared audit has been validated on actual pg_ivm Windows PR CI and the resulting `candidate-audit-native-pr` in [pg_ivm Run 39771145795](https://github.com/pgextwin/pg_ivm/actions/runs/39771145795). Its origin was [Windows PR Run 39769754052](https://github.com/pgextwin/pg_ivm/actions/runs/39769754052), exact head `5d593d2e642788743b4b521820286ac8871cb43f`; artifact ID `12422372611`. It was a read-only ZIP/SPDX/Grype/source-SHA 5/5 audit, **not** a formal signed Release or publication authorization.

## Purpose of this additional step

`scripts/bind-native-candidate-audit.py` (build PR #221) already defines a pure deny-by-default provenance join. The new `scripts/bind-native-candidate-audit-live.py` makes it usable from a **trusted protected-main Actions environment**, without a new App, Secret or privileged workflow. It independently GETs original PR/CI/audit-run metadata and exactly one matching audit artifact ID, reads the exact PR-head manifest from GitHub, downloads the real `candidate-audit-native-pr` payload by original Run ID, insists on exactly the two expected JSON files, and delegates to the central source-SHA/ZIP/SPDX/candidate binding library. Any stale main, PR movement, changed/extra source files, missing audit, status failure, wrong repository, duplicate or expired artifact fails closed. `tests/test-bind-native-candidate-audit-live.py` verifies these invariants.

This stage is **library/CLI only** and does not add any workflow listener, scheduled or write operation; a future guarded protected-main caller can use it read-only. The CLI requires real `GITHUB_REPOSITORY`, `GITHUB_REF=refs/heads/main`, allowed main-only event, and a read-only GitHub token. Output status remains `BOUND_NATIVE_CANDIDATE_AUDIT_NONPUBLISHING`, with **`publicationAuthorized=false`, `publishableReceipt=false`, and `signedArtifactsVerified=false`**.

### What is still unproven

It must not be wired as the Release publisher's receipt. A full automatic release requires a separate trusted event and explicit policy in the existing central and local promotion gates, exact GitHub required CI, per-version candidate decision, byte and Sigstore/SLSA/SPDX verification of the **signed** newly built Release, create-only tag reservation and release publication. The actual permanent shared Publisher is still manual-only; operator standing approval does not change what the deployed code accepts.

The fleet's existing manual-promotion fallback stays unchanged. The 17 extension listener PRs and each main/postmerge check should be fully verified before production publication migration. Catalog's separately signed Release intake remains independent.

Do not infer publication authority from a green read-only audit, re-label a failed run, bypass branch protections or issue premature Releases.
