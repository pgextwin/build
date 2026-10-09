# Step 23 — Nine-extension manual candidate queue

## Scope and safety contract

- All nine extension repositories use one central `metadata/automation-fleet.json` authority with `mode: BUILD`, `candidateEnabled: true`, `releasePolicy: manual-only`, and `scheduleUtc: 0 0 * * *` (09:00 JST).
- Every extension independently opts in through `config/candidate-build.json` with `enabled: true` and `releasePolicy: manual-only`. **Both controls are required.** The central rollout PR **must be merged last**, after all eight local opt-in PRs pass Windows CI and are merged.
- Watch and plan are automatic. Any newly detected stable upstream tag resolves to an immutable commit SHA, opens an automation-owned **draft** `auto-candidate/*` PR, and explicitly dispatches the existing Windows CI. If upstream is already current, no PR should be created.
- A candidate is **not** a release. No automatic candidate merge, formal Release, Catalog auto-merge, Website publication, or unattended-publication authorization is enabled by this rollout.
- `metadata/unattended-publication.json` stays `OBSERVE` / `DENY` with its existing automatic publication controls false. Do not set `UNATTENDED` or grant new Apps merely to operate this queue.
- Existing branch protection, checks, provenance, SBOM, vulnerability reports, release validation and packaging attestations remain in force. **Grype is currently report-only**; its result must be inspected manually until a blocking vulnerability policy exists.

## Manual queue runbook

1. Visit [fleet status](https://github.com/pgextwin/build/actions/workflows/fleet-status.yml), refresh its read-only report if necessary, and check each extension's [candidate workflow](https://github.com/pgextwin/plpgsql_check/actions/workflows/update-watch.yml). Confirm actual run completion and downloaded candidate-decision artifacts, not merely a green fleet summary.
2. Review each new automation-owned **draft** candidate PR. Verify upstream stable tag, immutable source SHA, release notes, source/license/security changes, PG-major mapping, current base branch, and identity marker.
3. Require the exact candidate branch's Windows CI for all applicable maintained PG majors, package ZIPs, SPDX SBOM, Grype report, and verified `candidate-audit` artifact; for a failure, ambiguous GitHub API result, missing artifact, moved tag, duplicate candidate, or unverified PG major, **do not merge or publish**.
4. A human explicitly approves and merges only a suitable candidate PR after required CI. Turning a draft PR ready for review and merging it are **manual actions**. A new upstream tag is never by itself sufficient authority to publish.
5. Formal release remains a **separate deliberate action**. `plpgsql_check` uses its main-only `promote.yml` with the candidate and approval PR receipts; **PR #8 must be merged before relying on its main ancestry verification**. The other eight currently retain the legacy `release/*` path, where manually creating/pushing the release branch starts attested build and automatic publication. Do not confuse that legacy path with the stricter `plpgsql_check` promotion gate or claim publication gate parity.
6. After verifying a published release and its immutable assets, synchronize Catalog and Website using their existing validated paths. Do not enable Catalog auto-merge, unattended publication, or new App permissions in Step 23.
7. Verify live GitHub Release, correct PG major assets, SHA-256, attestation availability, Catalog/Website links; record the result. Failed stages remain queued for manual remediation.

## Acceptance checklist

- [ ] Eight new local opt-in PRs merged with required Windows CI.
- [ ] Central fleet PR merged **after** local PRs.
- [ ] Nine local candidate policies and central BUILD settings consistent on main.
- [ ] Nine `update-watch.yml` dry runs have successful **candidate-decision** artifacts; a suppressed outcome means cutover is not yet live.
- [ ] Nine Windows `windows.yml` workflows pass for currently configured, supported PostgreSQL majors (including PG14 while supported where configured).
- [ ] At least one real upstream stable update has exercised SHA pinning, candidate PR generation, Windows CI, and candidate-audit before declaring the complete new-candidate path proven for all nine. Otherwise report the remaining paths as **NOT YET EXERCISED**.
- [ ] `releasePolicy: manual-only`, `unattended-publication.mode: OBSERVE`, and release controls remain unchanged.
- [ ] Separately decide whether to port `plpgsql_check`'s stronger formal promotion gate to the eight legacy release repositories in a later step.

## Recovery

To stop new candidate creation immediately, change the affected central fleet entry from `BUILD` to `WATCH` and `candidateEnabled` to false using a reviewed PR. Existing candidate PRs remain for manual triage. Never delete Releases, rewrite existing tags, or silently modify published assets as a rollback strategy.
