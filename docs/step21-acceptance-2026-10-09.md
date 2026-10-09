# Step 21 — verified release promotion acceptance record (2026-10-09 JST)

## Decision

**IMPLEMENTATION ACCEPTANCE: PARTIAL; PRODUCTION E2E: NOT TESTED; FORMAL PUBLICATION: NOT AUTHORIZED.**

The security controls are implemented in shared build, the pilot extension,
Catalog and Website. Only pgextwin/plpgsql_check is eligible for manual-approved
release promotion under a separate explicit central/local policy.

As of this record, upstream okbob/plpgsql_check latest stable is `v2.10.13`,
identical to the current packaging manifest. There is **no real new stable
candidate** to promote; no candidate approval, new tag, formal Release or
new Catalog distribution record is manufactured.

## Changed repositories and evidence

| Repository | PR | Main merge SHA | CI |
| --- | --- | --- | --- |
| pgextwin/build | [#40](https://github.com/pgextwin/build/pull/40) | `4d77eac5585a3e5f87fc0a8ebacfc9e2c3332b79` | [37916733265 PASS](https://github.com/pgextwin/build/actions/runs/37916733265) |
| pgextwin/build | [#41](https://github.com/pgextwin/build/pull/41) | `4b920a9682ed2af883187b94e03caec37c608589` | [37918407487 PASS](https://github.com/pgextwin/build/actions/runs/37918407487) |
| pgextwin/plpgsql_check | [#7](https://github.com/pgextwin/plpgsql_check/pull/7) | `96718940a807bb7173ea2734ac7a1edfc3be0ef6` | [37917627748 PASS PG15–18](https://github.com/pgextwin/plpgsql_check/actions/runs/37917627748) |
| pgextwin/catalog | [#19](https://github.com/pgextwin/catalog/pull/19) | `dd1df8e41a291b480b8fb20ec04ea353bfb70f87` | [37917750320 PASS](https://github.com/pgextwin/catalog/actions/runs/37917750320) |
| pgextwin/catalog | [#20](https://github.com/pgextwin/catalog/pull/20) | `3444e8a210013474b47792ccb4c723305962008b` | [37918008616 PASS](https://github.com/pgextwin/catalog/actions/runs/37918008616) |
| pgextwin/website | [#11](https://github.com/pgextwin/website/pull/11) | `2c2ffd73f08f5ade7335c4a65f07ae47d9e9e12d` | [37917642342 PASS](https://github.com/pgextwin/website/actions/runs/37917642342) |
| pgextwin/website | [#12](https://github.com/pgextwin/website/pull/12) | `99ab77fee8b760ad8dfa2bc7d496d38b9e580163` | [37917998706 PASS public HTTP + browser](https://github.com/pgextwin/website/actions/runs/37917998706) |

Follow-up [plpgsql_check PR #8](https://github.com/pgextwin/plpgsql_check/pull/8)
hardens full Git main ancestry checkout and connects the formal publisher to the
`formal-release` GitHub Environment. The PR's latest complete Windows CI
result and merge must be audited separately before marking this follow-up PASS.

## Formal Promotion Gate

The gate is activated ONLY by a trusted main workflow_dispatch, requiring
automation-owned, human-reviewed and merged candidate PR; aligned immutable
candidate-decision + VERIFIED candidate-audit; all maintained PG15–18 artifact
records; fixed upstream SHA; independently reviewed/merged JSON approval PR;
current source manifest; live central and local release permission; and a
never-used version/tag.

The candidate unsigned ZIP is NEVER reused as formal Release material.
Fresh build-extension-attested.yml output receives PACKAGE-INFO.json, SPDX 2.3,
Grype, build provenance and SPDX attestation. A separate release job rechecks
identity and attestations; a Git tag is exclusively reserved; draft assets and
SHA256SUMS are remotely downloaded and SHA-256 compared before creating a new
public Release and after publication.

A partial draft or reserved tag quarantines the run. Rerunning and replacing
previously published Releases/tags is forbidden. Details:
[step21-operations.md](step21-operations.md).

## Catalog and Website

Catalog `sync-release.yml` will accept ONLY a public signed Release, independently
verify each PG-major ZIP, SPDX and Grype digest (actual remote bytes),
SHA256SUMS, attestations, PACKAGE-INFO.json and the source commit. It uses
source-fixed Test Contract v2 and opens a **reviewable, not automatically
merged** Catalog v2 PR. Historical metadata for the other eight extensions
remains unchanged. Cross-repo dispatch uses a scoped short-lived GitHub
App installation token, NOT a personal PAT.

Website continues to load current Catalog as the sole Release data source.
It runs a live public HTTP byte-level audit and a separate headless Chrome
search/filter/mobile UX test. A production [run 37917998706](https://github.com/pgextwin/website/actions/runs/37917998706)
passed all public checks for the **existing** stable Release; this is NOT
evidence of a newly promoted Release.

## Preservation audit

- Existing `plpgsql_check` Release: `v2.10.13-windows.1` (Release ID
  `407329473`, 13 assets), published 2026-10-08 23:02:57 UTC.
- Existing tag ref still points to packaging commit
  `d057a38c39e892eb91fb9aef5e90af2cdd58ddb6`.
- Exactly one visible public `plpgsql_check` GitHub Release in the
  contemporaneous audit. No Step 21 release/tag was created.
- `metadata/automation-fleet.json` unchanged: pilot BUILD and other eight
  WATCH, daily 00:00 UTC, `manual-only`. PG14 EOL and PG19 readiness
  gates from earlier Steps unchanged.

## Blockers / operator-only steps

Use GitHub's UI to register/install the narrowly scoped Catalog/Website
Actions GitHub App; configure Client ID variables and private-key repository
secrets; permit Catalog bot-created PRs; enable appropriate branch protections,
human reviewers and the `formal-release` Environment Required Reviewers
on the **public** pilot repository. Inspect actual reviewer availability; a
sole human cannot supply two independent same-PR approvals without a distinct
PR author/reviewer arrangement. Do not bypass the gate for convenience.

Without a genuinely newer stable upstream source, the live newer-version
detection → candidate PR → actual Windows matrix → VERIFIED candidate audit →
human approval → fresh formal attested build → public Release → Catalog PR
and merged Website E2E is **NOT TESTED**. Only synthetic offline approval,
negative security tests and an existing-release public Website audit pass.

## Expansion to other eight Extensions

Separate audited release-policy opt-in is required per repository, after real
candidate E2E; verify tag/update strategy, source and license, PG major
matrix, Test Contract, signed output, approval reviewers and Catalog evidence.
Do not change the existing eight WATCH entries or enable automated
unreviewed publication during Step 21.
