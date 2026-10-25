# Publication-policy transition contract

The current deployment remains manual-only / manual-dispatch / OBSERVE /
Publisher DENY. This change does not activate publication or assert a signed
Release E2E. The source, branch, CI, signature, vulnerability, independent App,
local opt-in, original schedule and create-only gates remain mandatory.

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
