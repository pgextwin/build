# Issue #75 — Immutable dependency delta and isolated Reader (2026-10-17)

**Status: internal Git Blob subgraph documented; external transitive closure INCOMPLETE;
Reader runtime scopes NOT_PROVEN; signed Publisher positive prewrite NOT_PROVEN.
GO B/G4/G5 NO-GO; P1 65/70, independently accepted source 40/40, five
plpgsql_check PG14–18 historical rows DENY, P1 BLOCKED/P2 NO-GO; no Release.**

This work **does not** repin `plpgsql_check/promote.yml` or its actual old
Publisher `455f0ccc667697f600700a6e64bcfd6c57b6a977`, change the
Signer `5756b3c5136a8bf4db710016cfe97555f0a71c6d`, authorize a
Tag/Release, run a signer, or mint/use a Writer token.

## Actual four immutable source roots

Reused unchanged: [32 critical Git Blob evidence](../evidence/issue-75/critical-pin-closure-20261017.json)
and [existing inert validator](../scripts/issue-75-go-b-critical-pin-closure.py).
Immutable `git/trees?recursive=1` from GitHub independently returned
`truncated=false` for pilot
`98452723fcad2aedafb1c02a210f35950f7e8cf2`, legacy
`455f0ccc667697f600700a6e64bcfd6c57b6a977`, signer
`5756b3c5136a8bf4db710016cfe97555f0a71c6d` and reviewed,
**NOT DEPLOYED** current source `2fa0dd844fdef66e529c090625c6e6f0aa105a67`.
The later build/main `6306d320573307ce67ffe6a440e0ffa48163fcaa`
does not become the active Publisher automatically.

Additional immutable GET paths in
[delta record](../evidence/issue-75/transitive-dependency-delta-20261017.json):
Signer seven scripts (PostgreSQL install, Syft install, Grype install, SBOM
generate, vulnerability scan, SBOM validate, vulnerability report validate)
plus Grype config; pilot four `windows/ci/*.ps1` and
`config/export-audit.json`. Total **32 + 13 = 45 Git blobs**, with
**54** recorded source dependency edges and **16** external nodes.
The [bounded offline validator](../scripts/issue-75-transitive-dependency-delta.py)
rejects altered required SHA, root, missing edges, cycles, unknown target,
false closure assertions, floating binaries mislabeled as verified and
permission-boundary drift. It does **not** assert automatic discovery of every
possible dynamic child. Any newly identified edge requires evidence/validator
update and another protected PR. It never returns a Publisher authorization.

Git Blob SHA-1 is a *Git object identifier*, **not** an executable-download
SHA256. Syft `v1.54.1` and Grype `v0.120.1` installers contain
explicit ZIP SHA256 checks, but this work did not reacquire and hash the
ZIP bytes. The five Chocolatey PostgreSQL packages have explicit **versions
only**; `meson==1.8.3` and `ninja==1.11.1.4` are version-pinned without
wheel hashes; `jsonschema>=4,<5` is floating; Grype DB updates dynamically.
GitHub Actions are full Git SHA-referenced, but their **transitive action
dependencies** are not audited here. `windows-latest`, `ubuntu-latest`,
`vswhere -latest`, installed MSVC, Python toolcache and CLI runtime are
mutable. Upstream `ccdbcce9...` belongs to the **pilot main
v2.10.14**, not the open v2.10.15 candidate.

## Authentication and cross-job propagation boundaries

| Role | Static permission | Audited status |
| --- | --- | --- |
| Reader (new CI `issue75_reader_probe`) | `contents:read`, `actions:read` in PR-only job | Separate job-local `github.token`; existing GET-only observer transport, no third-party credentials, no shell `gh`, no Artifact, no Writer. Token's actual accepted privileges are **NOT_PROVEN** by static config or GET. |
| Signer (existing reusable workflow) | `contents:read`, `id-token:write`, `attestations:write`, `artifact-metadata:write` | The two `actions/checkout` steps in the Signer do **not** specify `persist-credentials:false`. The default persisted credential remains a recognized runtime propagation gap. Do not silently mark Signer credential isolation as proven. |
| Writer (actual existing `promote.yml`) | `contents:write`, `actions:read`, `attestations:read` | Separate publish job in another repository; **not started and no Writer token minted/used** here. No claim of actual credential-isolation proof. |

The new Reader checkout explicitly uses `persist-credentials:false`.
The probe's `GH_TOKEN` exists only for its one step and is never copied
to artifacts, Git config, or printed. Job-scoped read credentials are
**configuration evidence only** until the runtime GET job log is audited.
`issue-75-reader-isolation-probe.py` runs exactly two authenticated
allowlisted GETs against known **unsigned** Run `39021934569`. It reports
`PR_READER_GET2_NEGATIVE_ONLY` if stable; if denied or unavailable,
`GET_NOT_PROVEN`. Both mean **GO B NO-GO**. It cannot check effective
scope solely from a successful GET. The original
`issue-75-go-b-live-readonly.py` still handles genuine active Publisher
two-round topology checks in a separately authorized future read context.
No positive real signed Publisher topology is claimed.

The [new hostile tests](../tests/test-issue-75-transitive-dependency-delta.py)
run under existing required `resolver`. Reader GETs, GitHub authentication,
signed ZIP/attestation verification, negative Writer API simulations and
schema-v2 quarantine are independent gates: this static delta never upgrades
existing `UNKNOWN_QUARANTINE` classifier outputs, current Publisher
schema-v1 storage, or mock signed claims.

**Required next proof:** independently reviewed all dynamic external inputs,
actual action/Runner/toolchain digests and verified scoped job logs; then,
under separate valid approval, genuine active signed Publisher prewrite with
ten original-byte X.509 proofs and independent read-only double checks.
This PR never grants permission to publish.
