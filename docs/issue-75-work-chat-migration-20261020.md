# First Work setup and normal Chat handoff — 2026-10-20 JST

**Verdict: nonpublishing normal-Chat operation READY; end-to-end Chat-only formal Release NOT_READY.**

This setup is not a candidate UPDATE or individual PUBLISH instruction. All
three third-wave formal Releases remain absent. GO B/G4/G5 remain NO_GO.

## 1. Authenticated GUI audit and changes

Fresh Work Cloud Browser, signed in as the owner, inspected actual organization
Actions, App installation permissions/repository scope, all six targets’ Classic
main protection, Environments, Secret metadata, org runners and private-repository
filter. This is an **authenticated operator GUI observation**, not a signed
machine-readable effective-rule snapshot or a real Writer credential probe.
No Secret/key/token value was opened or recorded. No admin setting changed.

- Actions: all repositories/all actions allowed, full-SHA pin required, default
  contents/packages READ, existing Actions PR creation permission enabled.
- Existing Apps: ChatGPT Codex Connector has all-repo code/PR/workflow/actions
  writes and checks/status/metadata reads, **no Administration**; Classic auditor
  has Administration+Metadata READ on **plpgsql_check only**; Catalog proposer
  has Metadata READ and code/PR WRITE on **catalog only**. Neither scoped App is
  an independently authorized third-wave Release Writer; no scope was expanded.
- All six main branches: PR required, latest-head CI strict, approvals not
  required, actor bypass disabled, admin enforcement enabled, force/delete
  disabled. Required App15368 contexts: build `resolver`, Catalog `validate`,
  Website `lifecycle-tests`, three extensions `Windows required summary`.
  Catalog/Website retain existing stale-review dismissal. All six GET ruleset
  collections, including parent rulesets, were empty; Classic rules still apply.
- No Environment in build/catalog/three extensions. Website has `github-pages`
  with one protection rule; it is not a Signer/Writer environment. No repository,
  environment or available org Secret in build/website/three extensions.
  Catalog’s existing proposer key metadata is present; its value was not opened.
- Organization: 21 repositories, private filter (including archived) 0; runner
  list contains Standard GitHub-hosted only, no listed self-hosted runner.
  This does not prove global absence of an external private executor. No suitable
  approved independent execution environment was demonstrated.

No new App, credential, private repository, host, plan, cost, protection change or
third-party review requirement was introduced.

## 2. Implemented resources and exact evidence

Shared **build PR #144** adds the read-only reusable admission job and reuses the
existing strict authorization parser. Exact-head `ea59bf33570e2031bf47b169e9b5eaaa9c06b5ec`,
required App15368 resolver [PR Run 39347165087](https://github.com/pgextwin/build/actions/runs/39347165087)
SUCCESS; protected merge `3df403c22aeb220ebc75632b25a25550a863519c`;
[exact-main postmerge 39347218488](https://github.com/pgextwin/build/actions/runs/39347218488)
SUCCESS. PR-only SKIPPED jobs were not counted as executed.

| Extension | Protected PR / exact head | Merged main | PR Windows run | Main push run |
|---|---|---|---|---|
| pgtap | [#4](https://github.com/pgextwin/pgtap/pull/4), `afe3deb9f737b30251bac7288ac6e51a12b1db10` | `35e1f76a14eb4b962e3478d6359ccd39afc33aa5` | [39347365687](https://github.com/pgextwin/pgtap/actions/runs/39347365687) | [39348173513](https://github.com/pgextwin/pgtap/actions/runs/39348173513) |
| pg_variables | [#3](https://github.com/pgextwin/pg_variables/pull/3), `702a165e2e73f264762a605e1022624b2b156d64` | `6f9547521df2de9df295d9d6fabd916ffcc63a73` | [39347374602](https://github.com/pgextwin/pg_variables/actions/runs/39347374602) | [39348179617](https://github.com/pgextwin/pg_variables/actions/runs/39348179617) |
| pg_store_plans | [#4](https://github.com/pgextwin/pg_store_plans/pull/4), `a1f7195f5516ac2f6ef432881ca9ef256f4232a0` | `f895d8e7d7b8d632eecbc2f74f2c22f659fae85c` | [39347384135](https://github.com/pgextwin/pg_store_plans/actions/runs/39347384135) | [39348184925](https://github.com/pgextwin/pg_store_plans/actions/runs/39348184925) |

All PR Windows PG14–18 jobs **15/15 SUCCESS**, all three native required summaries
SUCCESS at exact head; CAS squash merge. No successful old Run was retried.
New postmerge results: all three parent runs COMPLETED/SUCCESS, all 15 maintained PG14–18 Windows jobs SUCCESS, all three native required summaries SUCCESS, attempt 1.

**Catalog PR #138** adds a no-Dispatch **read-only** protected request route using
the existing genuine public signed-Release verifier and GET-only client. It
creates a verified-record artifact for Chat’s normal protected Catalog record PR;
it does not mint/use the proposer App or write Catalog/Release state. Local
complete Python suite **391 PASS** (initial local missing jsonschema dependency
was installed before that successful full rerun). Exact head
`61379f3debc718a1cde193f2b92aa565d8a49d40`, [PR Run 39348250791](https://github.com/pgextwin/catalog/actions/runs/39348250791)
required App15368 validate and native Windows packaged CLI smoke SUCCESS.
Merged main `004dbea7fd503ff615b152c76a98a8c519516450`.
[Exact-main Validate39348440990](https://github.com/pgextwin/catalog/actions/runs/39348440990)
SUCCESS; [new route bootstrap39348440982](https://github.com/pgextwin/catalog/actions/runs/39348440982)
SUCCESS with `NO_CATALOG_REQUEST`, no record output or GitHub mutation. Its
verify job118386614951 emitted both Release-publication and Catalog-main-write
capabilities false.

**Public Website regression discovered and repaired:** the actual cross-repo
[audit39348441311](https://github.com/pgextwin/catalog/actions/runs/39348441311)
FAILED because live CLI pages had moved to v0.3.2 while the verifier still demanded
v0.3.1 and its old EXE hash. The failed run is retained; later checks were SKIPPED,
not SUCCESS. Website [PR #38](https://github.com/pgextwin/website/pull/38), exact head
`898fa278f74a4b2e135e0715cff185d25e7909a1`, native PR Run39349060753 both checks
SUCCESS, corrected obsolete labels and bound the served-HTML contract to the
existing public CLI Release417855312 / EXE657731413 SHA256
`d4e8f63d402066b21db9d537f7679b51137ec47d9834fa4fd75b5889ad34e6f4`.
64 local Node tests PASS including stale tag/hash/label, verbose and mixed-locale
negatives. Historical size-comparison text remains historical. Reusable audit
now self-pins checkout to `job.workflow_repository/job.workflow_sha` without
persistent credentials. Protected merge `54c06a57aa16d0687e9e2dc6710732db1ce2237c`;
[postmerge Validate39349133783](https://github.com/pgextwin/website/actions/runs/39349133783)
SUCCESS. [Pages deploy39349133690](https://github.com/pgextwin/website/actions/runs/39349133690) and [public audit39349133807](https://github.com/pgextwin/website/actions/runs/39349133807) SUCCESS: current CLI v0.3.2 EN/JA HTML/hash/verbose contract, real 14/70 ZIP/SPDX/Grype parity and headless Chrome JA/EN signed-release links/SHA256 plus mobile layout all passed.

Catalog [PR #139](https://github.com/pgextwin/catalog/pull/139), exact head
`f653ae7b989b3feafd5810c60e651f3024c20d2e`, refreshes only the full-SHA reusable
audit reference to that reviewed Website source. [PR CI39349194003](https://github.com/pgextwin/catalog/actions/runs/39349194003) native validate and Windows packaged CLI smoke SUCCESS; protected merge `c0dba8d3ee907b9f6602aafabd4545950e651ed2`. [Exact-main Validate39349427737](https://github.com/pgextwin/catalog/actions/runs/39349427737) and [actual cross-repository public Website audit39349428002](https://github.com/pgextwin/catalog/actions/runs/39349428002) both COMPLETED/SUCCESS, attempt 1. The earlier failed public run was not retried or waived.

Shared parser/observer/Phase C/D/G3/typed receipt/private-principal focused tests
55 PASS; new Catalog request 10 hostile tests and existing signed verifier 14
included in the 391. Unknown/missing/duplicate JSON, wrong repo/tag/ID/actor,
bot, stale SHA, failed/skipped/ambiguous CI, replayed attempt, blob mismatch,
main/Release races, pagination/redirect/API errors and unsigned/draft inputs deny.
All synthetic valid inputs are fixture-only; no live authorization/request JSON,
fake Release or tag was created.

## 3. Actual authentication and remaining proof boundaries

All three fresh PR and main-push read-only admission jobs succeeded. In real
main-job logs (authenticated API reads): actor, triggering actor, PR author and
merged_by are `ShutenOishi` (User); exact setup PR/head/main matched; squash
signature `verified=true`, committer `web-flow`; App15368 required CI SUCCESS on
the exact PR head. Thus this connector’s merges **really triggered** push Actions,
without a GUI Dispatch. This does not attest the words typed into Chat or prove
GITHUB_TOKEN-originated push semantics by an actual privileged bot experiment.

Real main observer jobs: pgtap `118385743253`, pg_variables `118385762636`,
pg_store_plans `118385780583`. Each emitted `NO_AUTHORIZATION`, `publication=DENY`,
`publishableReceipt=false`, `effectiveClassicProtectionVerified=false`,
`candidateSignaturesVerified=false`, `independentWriterVerified=false`.
No Signer/Writer was invoked. No production signature or Writer test is claimed.

## 4. Separate GO B / G4 / G5 verdicts

| Gate | Verdict | Concrete remaining proof |
|---|---|---|
| GO B | NO_GO | Approved isolated execution plus separately authenticated Writer, genuine signed actual-Publisher positive prewrite, token custody/nonpropagation and durable recovery. Existing 45 Git Blob roots/negative tests reused unchanged; no credential mint authorized here. |
| G4 | NO_GO | Genuine eligible candidate, fresh effective branch rules, independent Signer/Writer admission, explicit named human PUBLISH, real one-file authorization and JIT/create-only/replay acceptance. Format/actor/CI success alone is insufficient. |
| G5 | NO_GO | A newly authorized signed third-wave formal Release independently accepted through public original bytes/attestations, protected Catalog and Website JA/EN. There is no such Release to test. |

The original GO A Run39008743613 FAILURE was not rerun, waived or counted as
a successful whole-workflow gate. Historical approved manual Release operation and current real 14-member Catalog
are retained. Their success does not satisfy the new independent GO B/G4/G5.

## 5. Third-wave state and Catalog/Website

| Extension | Candidate config | Publisher | Formal Release | Live Catalog/Website |
|---|---|---|---|---|
| pgtap | enabled true; manual-only; no UPDATE performed | local disabled; not in formal allowlist | 0 | no formal record/ZIP |
| pg_variables | enabled true; manual-only; no UPDATE performed | local disabled; not in formal allowlist | 0 | no formal record/ZIP |
| pg_store_plans | enabled true; manual-only; no UPDATE performed | local disabled; not in formal allowlist | 0 | no formal record/ZIP |

Central formal Publisher stays **14** identities. Catalog index stays **14** real
extensions / **70** ZIPs; 14→17 intake and CLI **v0.3.2 verbose** retained. No candidate
ZIP or placeholder was admitted. Existing downstream Catalog-main → public
Website JA/EN audit retained, with the above CLI v0.3.2 regression correction and immutable source pin.
The new Catalog read-only path is bootstrap-tested with NO_CATALOG_REQUEST;
actual future signed request → artifact → record PR remains unproven without a
real eligible Release. Existing proposer App’s optional route is unchanged.

## 6. READY / NOT_READY

- **READY:** normal Chat + GitHub connector can implement/test/protect/merge,
  trigger actual read-only PR/main checks and prepare Catalog verification through
  protected PRs. No routine Work Dispatch is needed for these bounded operations.
- **NOT_READY:** normal Chat alone cannot yet complete strict third-wave formal
  publication. The shared observer deliberately has no publishing connection or
  valid receipt. No new privilege was hidden inside this change.

## 7. Exact remaining privileged work

Identify/authorize a suitable isolated execution and independent Release Writer
identity with least repository scope, short lifetime, governance separate from
Reader/Signer, no untrusted checkout exposure, genuine OIDC/certificate and signed
Publisher-positive proof, create-only/recovery and durable evidence. Check a
GitHub-Actions-only compatible isolation design first; external hosting or a new
App is not declared unavoidable merely from this inventory. Any necessary new
security-sensitive grant, key/secret provisioning or budget is a **separate**
concrete administrative authorization, not this setup. Existing Classic auditor
cannot be treated as authorizing its own expansion to the third wave; screenshots
cannot replace fresh runtime effective-rule proof.

A concrete privilege request, if needed after design review, must name all of:

| Resource | Minimum proposed boundary (not created or approved here) |
|---|---|
| Release Writer identity | Organization-governed App, selected exact extension repositories only, Metadata READ + Contents WRITE; no Administration/org/billing/workflow/action write grant. Per-publication installation token restricted to one target, at most one hour and promptly revoked. |
| Effective-protection reader | Separately governed Administration READ + Metadata READ on exact targets, never a Publisher; current pilot-only auditor scope is insufficient. Any expansion needs its own grant. |
| Signer | Genuine approved OIDC/certificate trust pinned to reviewed workflow/source/run/attempt; no Writer key/token in its job, workspace, artifacts or cache. |
| Runtime/custody | Explicit approved owner/location/isolation/credential store, trusted immutable source and required checks, no caller/candidate checkout execution with credentials, independent JIT and durable recovery. Existing public hosted CI and empty Environment lists do not prove this. |
| Cost | Keep current budget/plan unchanged. Do not assert zero cost or provision an external host before an actual authorized quota/cost boundary is documented. |

After that proof, use a protected production cutover PR, retain all required CI
and postmerge, then require each candidate UPDATE and each named human PUBLISH.
Never use the old github.token as an independent Writer or upgrade synthetic GO.

## 8. Copy-ready normal-Chat continuation

See [the complete continuation prompt](issue-75-next-chat-20261020.md). It tells
the next Chat to GET current Issues/main/CI, reuse this implementation/evidence,
retain formal DENY and finish only work within existing authorization. This
report does not authorize a live Release, candidate update, App/secret change or
new expenditure.
