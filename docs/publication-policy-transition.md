# Publication-policy transition contract

The protected central declaration supports `automatic-signed-schedule`, explicit
authenticated connected-Chat candidate merges and the independent Publisher App
in ENFORCE mode. Central readiness is not publication authority. Each extension
still needs its own protected local opt-in, current immutable support callers,
a fresh manifest-only original signed main/push and the genuine central schedule.
The source, branch, exact-head CI, Sigstore/SPDX, blocking vulnerability, scoped
independent App, token revocation and create-only gates remain mandatory.
During coordinated rollout, a manual local declaration remains denied.

| Stage | Meaning |
| --- | --- |
| Candidate policy and decision `manual-only` marker | Legacy candidate-only format. A candidate never authorizes a formal Release. Preserve this marker in both fleet modes. |
| Fleet `manual-only`, central/local `manual-dispatch` | Existing manually confirmed promotion path. |
| Fleet/central/local `automatic-signed-schedule` | Separate, explicit scheduled Publisher policy. Full unattended controls, ENFORCE and the independent App identity must agree. |
| Static policy readiness | Configuration consistency only; always `publicationAuthorized=false` and `publishableReceipt=false`. |
| Scoped App proof | Actual scoped WRITE and token invalidation evidence, still not Release authority. |

`fleet-policy.py` supplies one supported-mode/membership grammar for observation,
candidate generation, native audit binding, signing intent and scoped tokens.
Audited upstream identities remain a separate explicit source registry. Unknown,
mixed, duplicated and incomplete inputs are rejected.

Required CI validates the actual four-file declaration with the same function
used by the real Publisher issuer. Historical manual-only tests use a frozen
fixture instead of asserting that live metadata can never change. A required
test copies the repository into a temporary directory, projects the complete
automatic declaration and executes every existing Python suite in that copy.
It also rejects all partial combinations of the two policy bundles. No deployed
policy or local repository file is changed by this test.

Legacy manual promotion and the legacy-only handoff/admission diagnostics keep
their manual guards. The signed workflow selects those steps only when the
shared parser reports `manual_only=true`; the scheduled Publisher has its own
independent issuer and live checks. They must not be relabelled as automatic
authorization. Historical source/parity fixtures test that legacy behavior.

The shared signed-audit workflow now writes its `manual_only` output through
the common parser with an actual newline. The old inline parser wrote a literal
backslash-n, which could silently suppress the manual-only handoff steps.

Activation still requires genuine candidate and signature evidence, effective
central and local authorization, and current immutable caller references to
compatible code and policy snapshots. Changing these four metadata files alone
is not an activation procedure. Individual callers remain pinned; deployment
must coordinate their pins with the approved policy snapshot, preserve the
audited attested-builder pin and recheck protected source SHA/CI after changes.

Catalog has a fifth, separate declaration in
`metadata/manual-release-downstream.json`. Its historical filename does not
restrict its supported mode: `POST_MANUAL_RELEASE_ONLY` pairs with manual
promotion, while `POST_VERIFIED_RELEASE_ONLY` pairs with automatic signed
schedule. `catalog-downstream-policy.py` validates the actual declaration
against registered fleet membership. Disabled legacy pilot configuration
remains valid; an enabled declaration requires the complete fleet. Neither
mode grants Catalog write or Release authority. The future-policy CI copy now
projects this fifth declaration too, and manual-only regression tests use the
frozen historical fixture. The protected fifth declaration covers the complete
registered fleet; actual Catalog local/App/runtime opt-ins remain independent.

See [the review-only migration plan](publication-migration-plan.md) for the
generated fleet diffs, source invalidation rule, deployment order and independent
Catalog/CLI/Website prerequisites. Templates have no bound target policy SHA
and cannot be used as activation receipts.

Publisher selection preserves Catalog's completed-successful central Run
provenance contract. A failed independent proof matrix blocks publication;
neither a selected peer nor a JSON observation can waive that failure.
The additional per-repository selector excludes sources whose protected main
advanced after successful verification, before entering the Publisher
Environment. Network, authentication and cryptographic failures remain
failures. No failure is converted to success by `continue-on-error`.
