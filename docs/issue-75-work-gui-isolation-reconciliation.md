# Issue #75 — Work GUI audit reconciliation and safe isolated runtime requirements

Audit date: 2026-10-18 JST. Evidence source: **user-submitted Work Cloud Browser GET-only GUI report**. The normal connected GitHub App cannot independently retrieve organization administration, environment or App permission pages. Preserve source provenance. This document does not claim that current CI has independently reauthenticated the reported GUI screens.

## Reconciliation: what is absent and what is unknown

| Scope | Work GUI finding | Proof boundary |
| --- | --- | --- |
| pgextwin organization repositories | 18 total, all Public; Private filter 0, including archived | No private *repository in this organization* at time of GUI inspection; says nothing about other orgs, external clouds or isolated physical machines |
| build and plpgsql_check Environments | Both settings pages say there are no environments | No pre-existing repository Environment/reviewer gates in those two repos; cannot assume private approval workflow exists |
| Self-hosted runners | build and plpgsql_check each 0; org runner list Standard GitHub-hosted only; Default group 0, excludes public repositories | No preconfigured self-hosted/private execution pool in the inspected pgextwin views; GitHub-hosted public workflow SUCCESS remains true |
| Organization Actions | All repositories, all Actions/reusable workflows allowed, full-length SHA pin required | Action allowlist does not establish runtime credential isolation or independently signed provenance |
| Token/forks | Default GITHUB_TOKEN contents/packages read; private/internal fork PR disabled | Defaults do not prove job-effective scopes; the active Publisher explicitly declares contents:write and uses github.token |
| Licensing/budget | GUI plan GitHub Free, 2,000 Actions minutes/month; Actions $0 and Usage blocked UI | Paid/private-environment feature availability NOT PROVEN. The public main push Run SUCCESS is hard evidence that Usage blocked is **not** universal Actions execution failure. Licensing Not included labels for protections do **not** negate observed main protected=true and App15368 required resolver successes |
| GitHub Apps | GUI shows three organization apps: ChatGPT Codex Connector, pgextwin-catalog-proposer, pgextwin-classic-protection-audit | Clicking into the App pages was gated by Confirm access/sudo reauthentication; no scope/repository access read. Connector previously saw two app installations in its own scope. The 2-vs-3 count is not a contradiction: different access/visibility surfaces. No dedicated Release Writer identity proven |
| Signer/Writer | Old Signer OIDC permission is declared; Publisher Writer uses github.token | Real separately authenticated issuance, signed Publisher positive prewrite, and cross-job nonpropagation still NOT_PROVEN |

No token, Secret, private key, screenshot containing credentials or user session data is copied into public repo. No reauthentication challenge is submitted. The encoded machine-readable GUI summary is limited to non-sensitive numerical absence and explicit unknowns and is **not** a cryptographically authenticated policy snapshot.

## Implemented acceptance link

The original connector inventory (PR #131), existing 32+13 Git Blob closure, PR #129 real principal failure-closed admission, and PR #130 dormant private-only Signer/Writer code remain unchanged.

- `evidence/issue-75/work-gui-private-runtime-inventory-20261018.json` — narrow Work GUI report and its USER_SUBMITTED provenance. It does not include privileged App installation IDs or Secret metadata.
- `scripts/issue-75-work-gui-readiness.py --mode static` — validates both the **reported** pgextwin-local absence and previous connector/readiness contract; returns zero only for consistent negative observation. The output distinguishes `REPORTED_ABSENT` from `UNOBSERVABLE`. Successful CI never proves the GUI source itself was independently authenticated, or a real principal tested.
- `--mode require-real` — always denies exit 2. No fixture, well-formed JSON, App name, admin banner, plan feature, token declaration, CI success or Work screenshot may flip GO.
- `tests/test-issue-75-work-gui-readiness.py` — rejects falsified counts/provenance, out-of-scope global absence, premature real Writer/Signer/GO claims, untrusted JSON, credential-like keys and missing old evidence. The required App15368 resolver executes only these offline checks.

## Practical missing architecture and authorization conditions

**Recommended next engineering track:** design an **independent, isolated credential runtime that is not based on the current public GitHub Actions execution environment**. A private repository inside pgextwin is not currently present; GitHub Free plan labels alone do not justify assuming full private protected-env capabilities. An external privately managed runner/process may be an option only after its security configuration, approval and budget are verified. Do **not** create new infrastructure or change plan/budget without approval.

Minimum demonstrable prerequisites:

1. **Execution and authorization**: approved non-public hosting location, exact owner and tenancy, immutable protected source SHA, required CI, safe approvals before credential access, account quota/cost limits, independent audit actor. A newly created private repository **without** trusted protected secrets/job isolation does not meet this prerequisite. Existing pgextwin environments/self-hosted runners = 0.
2. **Three separately governed identities**: Reader restricted to GET-only; Signer controlled separately with genuine GitHub-issued OIDC/Sigstore certificate identity, immutable workflow/run/attempt and no Writer token; Writer a separately authenticated narrowly scoped short-lived GitHub App installation identity with the exact intended repository grant. The named Catalog and audit Apps are NOT presumed Writer-authorized without independent permission and provenance verification.
3. **Non-propagation**: separate runner/job credentials and storage; every checkout including nested/remote workflow persist-credentials:false; no tokens in output, artifact, cache, logs, command traces, process dumps, job summaries or build workspace; independent deny tests and audit evidence. Prior Signer five-checkout persisted-credentials gap still needs safely reviewed remediation in an approved code cutover.
4. **Provenance/cryptographic gate**: existing dormant `issue-75-private-signer-verify.py` must be executed using a genuinely pinned binary/trust root and real signed inputs; existing Writer app probe must validate authenticated installation source/scope/lifetime then revoke any *authorized test* token. Verify positive Publisher prewrite with genuine signed bits and schema-v2 crash safety before considering any promotion. A real Writer token mint is still a write-capability grant even if nothing is published, so requires explicit applicable authorization and isolated execution.
5. **Fail-closed fallback**: absent any independent proof, do no privileged experiment; keep source-only tests/GET-only inspection and historical evidence; never weaken protection, bypass CI, silently repin production Signer/Publisher, waive failed GO A, assume a 403 means nonexistent, or publish.

Evidence classification is **PRIVATE_EXECUTOR_NOT_PROVEN**, not unconditional GLOBAL_PRIVATE_EXECUTOR_ABSENT. For the inspected in-organization targets the specific absence is confirmed by the provided Work report; an external/private infrastructure might exist outside inspected surfaces, but no suitable one has been demonstrated.

Maintain formal P1 65/70, independent source 40/40, plpgsql_check historical PG14–18 five DENY, GO B/G4/G5 NO-GO, formal Release/distribution DENY. No configuration, Secret, permission, budget or GitHub App change is authorized by this report.

Next low-risk action: use this evidence to prepare a precise *authorization and private architecture readiness package* for an actual isolated runtime, without provisioning it. Only if such a runtime and the existing safety gates are independently authorized should positive-credential checks be considered.
