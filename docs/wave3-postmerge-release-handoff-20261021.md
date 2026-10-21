# Wave 3 — verified candidate-to-release handoff (2026-10-21 JST)

**Scope:** pgTAP, pg_variables, pg_store_plans only. This is a durable
**nonpublishing evidence and next-operation record**, not a PUBLISH request,
promotion authorization, Gate B/G4/G5 acceptance, or a source of cryptographic
signature/attestation truth. See [#141](https://github.com/pgextwin/build/issues/141)
and [#75](https://github.com/pgextwin/build/issues/75).

## Reusable immutable inputs

Central protected `build/main`:
`627009c72e73c296a3ca110fc6f1b25728fcec1f`
(PR [#182](https://github.com/pgextwin/build/pull/182),
[#183](https://github.com/pgextwin/build/pull/183)).
These are **historical exact-SHA observations**; re-GET before any future mutation.

| Item | pgTAP | pg_variables | pg_store_plans |
| --- | --- | --- | --- |
| Repository | `pgextwin/pgtap` | `pgextwin/pg_variables` | `pgextwin/pg_store_plans` |
| Upstream release | `v1.3.4` | `v1.2.1` | `1.10` |
| Pinned upstream SHA | `968eb53a33114e83042b3bdb0c664b5b80cf8bdf` | `1d1bfe26a5e2eec6dda761565e1307d679b1072b` | `e802804d4d2763ad3b32fc8fcf9f218c61cc475f` |
| Merged initial candidate PR | [#7](https://github.com/pgextwin/pgtap/pull/7) | [#6](https://github.com/pgextwin/pg_variables/pull/6) | [#7](https://github.com/pgextwin/pg_store_plans/pull/7) |
| Candidate PR exact HEAD | `4da263b3b1942473491774ad73a54f9502cd6c12` | `c20d19e388b83fbf42dfab1b7f5be1acc826f813` | `e91923f8fb25ee2ade8c46bfd1982acfc1bc7a87` |
| Human UPDATE decision run | [39501584646](https://github.com/pgextwin/pgtap/actions/runs/39501584646) | [39501692833](https://github.com/pgextwin/pg_variables/actions/runs/39501692833) | [39501818103](https://github.com/pgextwin/pg_store_plans/actions/runs/39501818103) |
| `candidate-decision` artifact ID | `12301580774` | `12301665899` | `12301750926` |
| Exact-HEAD candidate Windows Dispatch | [39501699629](https://github.com/pgextwin/pgtap/actions/runs/39501699629) | [39501793286](https://github.com/pgextwin/pg_variables/actions/runs/39501793286) | [39501929875](https://github.com/pgextwin/pg_store_plans/actions/runs/39501929875) |
| `candidate-audit` artifact ID | `12301836474` | `12301387411` | `12302505903` |
| Protected postmerge main SHA | `c5a88f12567c7a5ec42ae76b2cf8d281efd7d38d` | `3646c742ea72308f318a69ebae0fedeaef351c9b` | `9745cc3c613a3649bc24fc1a616c6fee87385dc6` |
| Actual main/push Windows run | [39514298953](https://github.com/pgextwin/pgtap/actions/runs/39514298953) | [39515310159](https://github.com/pgextwin/pg_variables/actions/runs/39515310159) | [39515322858](https://github.com/pgextwin/pg_store_plans/actions/runs/39515322858) |

- Latest authenticated GET on 2026-10-21: all three candidate Dispatch runs **COMPLETED/SUCCESS**, five PG14–18 artifact sets plus unexpired `candidate-audit` artifact in each; UPDATE runs COMPLETED/SUCCESS and `candidate-decision` artifacts present. Initial candidate PRs are **MERGED**.
- Previously independent **ZIP raw-byte** SHA256 verification: 15/15 matched the immutable `candidate-audit` digests; SPDX 2.3 and Grype JSON were present with zero reported matches, as recorded in [#141 evidence](https://github.com/pgextwin/build/issues/141#issuecomment-6303035379). Presence and Grype=0 do **not** imply signed authenticity or no vulnerabilities.
- All three native **main/push** runs are COMPLETED/SUCCESS at current protected main SHA, PG14–18 **15/15**, App15368 required `Windows required summary` **3/3**, nonpublishing `publication_admission` **3/3**. Their `Verify immutable Windows candidate ZIP, SBOM and Grype` jobs are **SKIPPED** (different event), not passed. [Final evidence](https://github.com/pgextwin/build/issues/141#issuecomment-6304227728).
- All three current `config/initial-release-candidate.json` files are first-release, pinned upstream source and `manual-only`. They are **not** Release signatures.
- Original failed push runs 39509961637, 39509969143, 39509978846 and intermediate failures remain historical failures and are **not** exempted.

## Promotion gate — current state (DENY, not an instruction)

1. Public GitHub Releases currently **0/3**. Every target `config/release-promotion.json` has `enabled=false` and `releasePolicy=manual-dispatch`. Central `metadata/release-promotion.json` excludes these three and retains only the approved 14; Catalog `index.json` likewise lists only 14. Do **not** change policies or Catalog public records merely because this candidate audit passed.
2. Real, independently governed **Reader/Signer/Writer** custody and target-scoped Writer token issuance, OIDC/Sigstore X.509 issuer/run/attempt, protected executor, signed **original** ZIP+SPDX+SLSA provenance, and positive Publisher prewrite/recovery have not been accepted. A checkout-hardening change on central main does **not** repin or validate old immutable Signer calls.
3. Effective Classic branch-protection REST/GraphQL proof by an appropriately scoped **independent Administration:read** principal is still missing. Normal GitHub connector's `/branches/main/protection` GET returns **HTTP 403 on all three**; `protected=true` and App15368 CI success do not replace that proof.
4. No per-target new authenticated human **PUBLISH** instruction, no accepted G4/G5, no publishable authorization receipt. **GO B/G4/G5 = NO_GO; publication = DENY.**
5. Candidate ZIPs are **unsigned candidate artifacts**. Signed formal Release/attestation/SBOM verification, Catalog inclusion, CLI resolution through public Catalog, Website EN/JA and public download verification remain **unexecuted** for these three.

## Smallest safe next execution sequence

- Preserve the initial candidate PR, original decision artifacts, hashes and success history. Before any privilege change, independently validate current App identity and audited effective rules for all three exact repository IDs (`1425678353`, `1425679720`, `1425680909`), with fresh authenticated proof and no secret disclosure.
- Separately obtain authorized isolated Signer and Writer custody, real short-lived scope/revocation proofs, signed Publisher-positive prewrite and durable create-only recovery; protect existing branch/required CI. Use previously implemented offline adversarial gate code rather than a parallel pipeline. Any new App/Secret/Environment or permission change requires its own explicit owner authorization.
- Only after each prior gate passes, obtain a **distinct explicit human PUBLISH** for the named eligible candidate and revalidate all exact main/candidate/decision/run identities, maintained PG majors, signature/attestation, tag nonexistence and tag create-only constraints; use only the approved promotion route.
- For each *actually published and independently verified* Release, submit only its scoped Catalog record to a **protected PR**, verify required exact-head CI and protected merge, then verify live CLI/public ZIP digests and both English/Japanese Website pages. Do not stage an unsigned Catalog download record.
- Record new positive or negative evidence to Issues #141/#75. If gate evidence is missing, **stop only that privileged release**; nonpublishing CI, documentation and unrelated extension work continue.

**No live credentials, Release, Tag, Catalog/Website/publication policy mutation or PUBLISH request was made by this handoff.**


## 2026-10-21 — dormant shared promotion source compatibility preparation

Protected central source proposal changes **only the source copy** of
`.github/workflows/promote-verified-release.yml`: both gate and Publisher
checkout references move from the historical 14-only
`455f0ccc667697f600700a6e64bcfd6c57b6a977` to reviewed build commit
`dd4d35186edccfbf39b40d86cecb28380cf210da` containing the 17-member identity allowlist, strict
initial-release bot intent parser and current fail-closed Publisher code.
The shared Signer `@5756b3c5136a8bf4db710016cfe97555f0a71c6d`
is unchanged. Its independent live signed/attestation/publisher acceptance
**has not happened**. This is **not an operational signer/publisher repin**.

Existing `plpgsql_check` and the three Wave3 `promote.yml` callers still
use their immutable shared workflow `@acd6eb28be6d750e89b626fa4ccd4403e1265cd6`,
which still points at the 14-only `455f0ccc667697f600700a6e64bcfd6c57b6a977`.
No local release-promotion flag, central 14-only allowlist, human `PUBLISH`,
private credentials, workflow dispatch, Tag/Release, Catalog, Website or
publicly effective promotion behavior changes in this source-only stage.
A later **separately authorized** Wave3 caller repin requires independent
Signer/Writer/Publisher source and runtime validation, exact protected PR CI,
real signing/attestation acceptance, and distinct human per-release PUBLISH;
never infer that central main alone upgraded pinned callers.


## 2026-10-21 — avoid accidental opt-in to Catalog Actions dispatch

In the **dormant shared promotion source** only, downstream `catalog_sync`
now requires both explicit
`PGEXTWIN_CATALOG_DISPATCH_ENABLED=true` **and** the
`PGEXTWIN_CATALOG_APP_CLIENT_ID` variable. A mere client ID is insufficient
to run a write-capable cross-repository `workflow_dispatch`.
`catalog_not_configured` reports blocked when either is absent. Only the
already existing `pgextwin/catalog` dispatch workflow receives the
extension/tag inputs; it must independently re-download verified published
Release bytes and create a protected record proposal after signed checks.

The **existing Catalog proposer** uses scoped Contents/Pull requests WRITE
inside Catalog to create one record PR; it is **not** an Actions WRITE
dispatcher. A dedicated Catalog-only Actions WRITE app must be separately
approved, installed and positively authenticated before setting the flag.
This source-only fix neither installs an App nor changes an active caller.
The current 3 Wave3 release candidates remain PUBLISH DENY, no Release/Tag.

## 2026-10-21 — final 17/17 UPDATE closure and formal Release boundary (live GET)

This section is a **new live observation**, superseding historical SHAs above
*only for the scope explicitly listed here*. It is neither approval to change
Release policies nor a PUBLISH instruction.

### Protected merge and postmerge — all accepted, no rerun required

The 17-extension automatic UPDATE refactor is present on all protected main
branches, and all 17 corresponding native main/push CI runs completed
SUCCESS. The *last* three reviewed first-Release repositories are:

| Extension | Exact protected main SHA | Actual main/push Windows run |
| --- | --- | --- |
| pgtap | `988bb997a2ed9ac83679a9eac9c7f2475a3b1347` | [39558315509](https://github.com/pgextwin/pgtap/actions/runs/39558315509) |
| pg_variables | `c522e63b5867ed65e0037b4c09719c98eb414b8d` | [39558265615](https://github.com/pgextwin/pg_variables/actions/runs/39558265615) |
| pg_store_plans | `382426d6df7e060f72b8c058a503cdca88021fbe` | [39558370902](https://github.com/pgextwin/pg_store_plans/actions/runs/39558370902) |

Each actual `event=push`, `head_branch=main` run had PostgreSQL 14–18
**5/5 SUCCESS**, the App15368 `Windows required summary` SUCCESS and
nonpublishing `publication_admission` SUCCESS. The latest protected
`update-watch.yml` uses the scheduled central verifier at
`39a329fb5e7c7f801eef3a23688fdd76cce8b2ac` and has no operator
`confirm_update` or manual `workflow_dispatch`. This does **not** prove
the first successful real cron-to-candidate PR end-to-end operation.
[Immutable completion report](https://github.com/pgextwin/build/issues/141#issuecomment-6310607813).

### Formal Release readiness — still DENY, exact unresolved gates

- Fresh public GitHub Release GET returns **0/3** for these repositories;
  per-repo `config/release-promotion.json` still has `enabled=false`
  and `manual-dispatch`. The central
  `metadata/release-promotion.json` still allowlists 14 only.
- Fresh authenticated GET to each Wave3
  `/branches/main/protection` returns **403**
  (`Resource not accessible by integration`): no independent
  effective-Classic-protection proof from this connector. Public
  `/rulesets` returns an empty array; do not infer absence of Classic
  protection or permission to bypass it. The exact repo identities are
  pgtap `1425678353`, pg_variables `1425679720` and
  pg_store_plans `1425680909`.
- Actual immutable Signer used by the historical shared publication
  `build-extension-attested.yml@5756b3c5136a8bf4db710016cfe97555f0a71c6d`
  has **five checkout occurrences, zero `persist-credentials:false`**
  declarations. The current central Signer source has the improved
  checkout pattern, but an unpinned source edit does not repair an old
  immutable caller, nor independently prove live X.509/Sigstore identity.
  Do **not** repin the live Signer before protected transitive provenance,
  signed-byte validation and independent credential isolation acceptance.
- Separately governed credential custody, scoped Release Writer GitHub App,
  real mint/revocation and live Publisher positive prewrite/recovery are
  unaccepted. GitHub `GITHUB_TOKEN` contents:write in an existing workflow
  is **not** evidence of independent Writer custody.
- No separately authorized human `PUBLISH` for these specific Releases;
  GO B/G4/G5 remain **NO_GO**. An UPDATE request, successful candidate,
  protected merge or signed Catalog verifier cannot substitute for it.

### Minimum subsequent execution, without repeating completed work

1. Use the already selected `pgextwin-classic-protection-audit` App
   with Administration:read to independently prove **effective** protected
   main on the three pinned repository IDs. Preserve permissions and
   installation selection; a 403 via the normal Chat connector is not proof.
2. Independently accept actual immutable Signer provenance/ZIP and SPDX
   signatures, credential isolation and scoped separately governed Release
   Writer/Pubisher issuance and revocation. Reuse the existing negative
   tests and Publisher prewrite/recovery contracts, do not create new
   experimental pipelines, and do not relax mandatory protection.
3. Only upon **all** existing release gates and a distinct user `PUBLISH`
   for an exact named/tagged candidate: use the existing manual create-only
   promotion route. Otherwise stop **only** the privileged publication.
4. For each actually published and verified official Release, use the
   **existing** independent signed Release verifier in Catalog, create a
   protected one-record PR, require exact-head CI, verify CLI public
   downloads and the EN/JA Website. Never seed Catalog from unsigned
   candidate ZIPs.

This checkpoint creates **no** live credential, App, Secret, Environment,
promotion flag, Release, tag, Catalog record, or PUBLISH authorization.
