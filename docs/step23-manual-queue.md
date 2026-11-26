# Verified Release and Catalog registration runbook (current procedure)

> Current operating procedure (2026-11-26). This runbook replaces the former 14-extension manual queue procedure. The original **Step 23 nine-extension** dry-run acceptance is recorded and completed in [build #47](https://github.com/pgextwin/build/issues/47); the continuing platform work is tracked in [build #61](https://github.com/pgextwin/build/issues/61) and [build #311](https://github.com/pgextwin/build/issues/311).

> For day-to-day operation, read the [Chat-first minimal publication guide](chat-first-publication.md) first; it is the primary operating contract. This runbook preserves the detailed verification and recovery procedures and the current Catalog registration evidence trail.

## Operating contract

- Central `metadata/automation-fleet.json` on protected `main` registers **26 extensions**. Each extension also has `config/extension.json` with an immutable upstream identity and its supported PostgreSQL majors (currently PG15–19; PG14 support ended). Central and local authorization must both pass.
- The genuine hourly schedule (`fleet-upstream-watch.yml`, minute :07 UTC) is stable-only. It may prepare a SHA-pinned automation-owned **Draft** `auto-candidate/*` PR and dispatch Windows CI. Upstream already current means no new candidate PR. A candidate is **not** a formal Release.
- Formal publication happens only through the established Publisher paths (the automatic signed-candidate route and the owner-source route), both fail-closed with `PUBLISH_DENY` as the default state. `metadata/unattended-publication.json` remains **OBSERVE / DENY**; no unattended formal Release or Catalog merge is authorized by policy alone.
- Maintain full-SHA pins, branch protection, exact-head PostgreSQL Windows CI, PACKAGE-INFO, SPDX SBOM, attestation and immutable checksum requirements. Grype results are recorded as evidence on each route; the per-route publication effect of Grype/SBOM follows the route's own current contract, not this runbook.

## Review a candidate — not yet a Release

1. Open the read-only fleet status and the target extension's own update-watch workflow. Inspect the latest applicable completed run and the actual scan/candidate artifacts. **A green fleet summary alone is insufficient.**
2. For a new Draft candidate PR, verify the stable upstream tag/ref, resolved **full immutable upstream commit SHA**, manifest-only diff, upstream release notes, license/security impact, PG-major mapping and automation identity. Reject missing/ambiguous API data, a shifted upstream tag, a duplicate PR and unexpected changes. Per-version license verification is mandatory for the exact version being packaged.
3. Require the candidate's **exact head** Windows CI success for every currently supported and configured PostgreSQL major, plus the independent signed-candidate audits (separately re-downloaded original bytes with real Sigstore verification). Do not treat a prior commit's successful run as a current-head check.
4. A verified candidate PR may be merged **after required CI** under the existing branch rules. An independent human reviewer is **not** separately mandatory, but verification and branch rules may not be bypassed. Record the candidate PR number, exact SHA and the relevant run IDs.
5. If a candidate is suppressed, its audit is missing, any matrix job failed, or upstream identity cannot be proven, **do not merge and do not publish**. Fix the source or evidence and repeat verification; never use an unrelated prior green run.

## Publish a formal Release — Publisher paths only

1. Confirm the current protected main, that all inputs still match the merged candidate and the latest correct head, and that the proposed release tag has **never** been used by either a tag or a Release.
2. Publication is executed by the dedicated Publisher (automatic signed-candidate route, or the owner-source route via the owner's authenticated commands on [build #311](https://github.com/pgextwin/build/issues/311)). The Publisher independently re-downloads the original signed bytes, re-verifies signatures and per-major SHA-256, and re-checks live authorization (current protected main, original Run/attempt, policies, tag vacancy) immediately before writing. There is no manual `promote.yml` PUBLISH path anymore.
3. The writer is create-only: it compares the local SHA-256 immediately before upload, compares the draft Release ID, asset set and host-side digests, and publishes that same Release ID. After publication it re-downloads the public assets and re-hashes them; a mismatch or incomplete post-publish audit leaves the Release in `PUBLISHED_AUDIT_PENDING` and blocks completion sign-off — the already-public Release is not replaced or deleted.
4. **If any stage fails:** do not count it as published, do not reuse an occupied tag, do not delete/overwrite previous public ZIPs, and do not silently retry a partial Release. Inspect the recovery evidence and address the failure under a separate explicit plan.

## Catalog registration — automatic proposal, independent re-verification

1. Only a **public, formally published** Release is eligible. Catalog's source of truth is `identities/<name>.json` (extension identity) plus the versioned ledger `packages/<name>.json` on `pgextwin/catalog` main. There is no hand-edited `extensions/<name>.json` merge step anymore.
2. **First registration of an extension** (a new `identities/<name>.json`) goes through a protected Catalog PR with required CI and review under the branch rules, like any other protected change. Do not create identity records through the automated release flow.
3. For a new Release of a registered extension, `sync-verified-release.yml` proposes a registration PR that updates only that extension's `packages/<name>.json` ledger record. Before merging, the record is independently re-verified against the public Release: the verifier re-downloads the public ZIP/SPDX/Grype assets and `SHA256SUMS.txt`, checks digests, PACKAGE-INFO identity and both signature predicates, and compares them with the proposed ledger row. `auto-merge-verified-release.yml` merges the PR only when every required check passes; a failed or incomplete verification leaves the PR unmerged.
4. After the registration PR merges, the signed Catalog feed is regenerated from the ledger, and Catalog Pages is deployed from the same main (`pages-deploy.yml`, https://pgextwin.github.io/catalog/). A successful Build or Release **does not automatically mean Catalog or Website have updated** — verify each step's own evidence.

## Post-publication verification (real fetch, both languages)

1. Independently fetch every required PG-major ZIP and companion SPDX/Grype asset plus `SHA256SUMS.txt` from the public Release; verify SHA-256 digests, the GitHub digest, PACKAGE-INFO identity and tag ancestry.
2. Verify the Catalog side: the merged `packages/<name>.json` record, the regenerated signed feed entry, and the Catalog Pages entry for the extension.
3. Verify the public pages in **both Japanese and English**: extension name, version, description and download links must render correctly and every download link must resolve to the verified public asset.
4. **Verify it yourself as a user:** download the package through the published CLI (or from the Catalog page), then compare the SHA-256 of the saved ZIP with the value in `SHA256SUMS.txt` / the signed feed before installing. A download whose digest differs must not be installed; report it instead.
5. Record the actual tag, Publisher run, Catalog PR/CI, feed result and public outcome in [fleet issue #61](https://github.com/pgextwin/build/issues/61).

## Acceptance tracking

- [x] Original nine-extension dry-run candidate-decision artifacts and public Website smoke — [Step23 #47 completed](https://github.com/pgextwin/build/issues/47).
- [x] Central candidate lanes for the full registered fleet — central `metadata/automation-fleet.json` (26 extensions), genuine schedule scan, read-only fleet status.
- [x] Catalog v3 registration: `identities/` + `packages/` ledger, automated registration PRs with independent re-verification and auto-merge, signed feed, and Catalog Pages are live.
- [ ] Audit every remaining new main-push Windows run after cutover; do not assume completion while jobs are in progress.
- [ ] At least one **new genuine stable update** per relevant strategy needs the full real path: candidate PR → SHA pin → Windows CI → dual signed audits → Publisher → Catalog registration PR → public Pages/CLI verification. Successful dry-runs alone do not prove this.

## Safe rollback

Disable an affected candidate lane with a reviewed central policy change (for example `candidateEnabled=false` in `metadata/automation-fleet.json`), plus any necessary local candidate opt-out. The formal Release gate stays fail-closed and explicit. Existing candidates require triage, but **existing Release tags, ZIP assets, attestations and checksums must never be deleted or rewritten as a rollback**. Keep original failures and receipts as audit evidence.
