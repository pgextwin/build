# Explicit candidate and Catalog merge identities

Unattended policy schema 2 distinguishes two existing trust routes. It does
not claim that a dedicated candidate merge App exists. The candidate route is
the authenticated connected-Chat operator: the original protected main push
sender and merged PR actor must both be the existing allowed human account.
The live postmerge bridge and the typed policy share one immutable central
allowlist in `candidate-merge-identity.py`. Bot authorship of the original
candidate is a separate, unchanged requirement.

The Catalog route still requires its existing dedicated repository-scoped App,
its own local opt-in, exact-head required CI, independent public asset and
Sigstore verification, and token revocation. The Catalog downstream field
`requireDedicatedMergeApp` and all live Catalog App checks are unchanged.
Signer and independent Publisher identities and permissions are unchanged.

Schema 1 remains supported for frozen historical/manual regression fixtures.
Schema 2 replaces its ambiguous broad `requireDedicatedMergeApp` control with
two mandatory positive controls: `requireTrustedCandidateMergeIdentity` and
`requireDedicatedCatalogMergeApp`. The additional `candidateMergeIdentity`
object requires the exact `authenticated-connected-chat` mode, shared allowed
actors and `requireSamePushAndMergeActor=true`. Unknown actors, App/bot modes,
partial controls and alternate identity shapes are rejected.

`unattended-policy.with_explicit_merge_identities()` returns a review copy. It
preserves OBSERVE/UNATTENDED and every automation switch, does not write files,
and produces no token or receipt. It cannot establish that a merge or App proof
actually occurred. Static validation still returns publication authority false.
The protected schema 2 declaration uses the actual connected-Chat identity
proved by candidate PR #79 and original signed push Run40250416760. The original
GitHub metadata does not claim a dedicated candidate App. The independent scoped
Publisher and Catalog App remain separate. Each future release must re-establish
its own live evidence after local policy/caller rollout; no declaration or prior
source proof substitutes for those runtime gates.
