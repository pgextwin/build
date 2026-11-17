# Shared owner-source readiness

The owner issue-comment route is already shared. An extension supplies its
manifest, test contract, Windows hooks and an issue number to
`.github/workflows/chat-signed-main-source.yml`. Repository identity comes from
the original GitHub context and the immutable central fleet; do not copy an
extension-specific authenticator, signer, audit or admission implementation.

The caller below is identical for pg_permissions and pg_track_settings. Keep it
at `.github/workflows/chat-signed-main.yml`: that path is part of signed source
identity. The event-only condition skips the PR invocation. The shared workflow
checks the command, owner, issue, main ref and attempt before authenticating the
live comment, protected main and original run using `chat-signed-main-auth.py`.
The builder independently repeats authentication with `finalize-owner-source.py`.
No local copies of those authorization conditions are needed.

```yaml
name: Genuine owner on-demand protected-main signed Windows source (NO RELEASE)
run-name: Chat-main-sign-comment-${{ github.event.comment.id || 0 }}

on:
  issue_comment:
    types: [created]
  pull_request:
    paths:
      - .github/workflows/chat-signed-main.yml

permissions:
  contents: read

concurrency:
  group: owner-main-signed-${{ github.repository }}
  cancel-in-progress: false

jobs:
  signed_main_source:
    name: Authenticate owner Issue 1 and attest true protected main (NONPUBLISHING)
    # Owner, issue, main, attempt and fleet identity are authenticated centrally.
    if: ${{ github.event_name == 'issue_comment' }}
    permissions:
      contents: read
      issues: read
      actions: read
      id-token: write
      attestations: write
      artifact-metadata: write
    uses: pgextwin/build/.github/workflows/chat-signed-main-source.yml@834f9ce912f2e5ce12834b77a9bd0ad7064554f9
    with:
      request_issue: 1
      extension_config_path: config/extension.json
      test_contract_path: config/test-contract.json
```

## Pin chain

The caller pin shown is the verified build main at preparation time:
`834f9ce912f2e5ce12834b77a9bd0ad7064554f9`. Its shared source workflow uses the
approved inner builder `cdb253b5167031264e1baea634b55934c5f91d59`, which exactly
matches `chat-signed-main-audit.py:OWNER_SIGNER_SHA`. Both commits have fleet blob
`0ae80c704a51c3d72fdea2864df4f6cc6d589df4` (19 members, including both SQL-only
extensions). No inner pin change is needed for this passenger. An outer caller
pin upgrade does not require changing the signer digest when that builder and
its fleet remain correct. Do not conflate the separate scheduled/push signer
with this owner-source signer, or broaden the accepted signer to a wildcard.

## Shared proof and admission

The shared workflow produces the intent, signed ZIP/SPDX/Grype files for each
maintained major, independent first/second audit receipts and the dual join.
Job names, artifact names and caller path stay unchanged so existing
`publisher-owner-source-admission.py:admit()` can re-fetch and audit the original
source twice. For PG15–18 this is nine successful jobs, four signed file triples
and four proof artifacts. No per-extension source admission adapter is needed.

`publisher-owner-source-publish-request.py` selects the owner source by calling
that same `admit()` after authenticating a distinct publication request and
checking the existing central/local opt-ins. It consumes neither a Catalog
registration nor a previous central admission-run receipt. The scheduled/push
candidate intake is a separate source route; never relabel an owner comment as
a push. The admission result always carries `PUBLISH=DENY` and no publication
or writer authority. Signing and publication remain separate authorized actions.

For pg_permissions the local manifest pins upstream `REL_1_4_1` / `1.4.1`,
commit `3360447e0668fed2b9db6a0ae1d086533781f9bd`, PG15–18 and upstream LICENSE
verification. Its SQL default version remains `1.4`. Existing central fleet and
policy allowlists already include it. The previous signing run is for an older
main and is not current-source proof.

## Readiness and later operations

A caller PR supplies readiness only. After it is reviewed and merged by an
authorized operator, verify the new protected main SHA and the immutable outer /
inner pin chain again. A separately authorized original owner signing comment
on the configured issue would then produce a new attempt-1 run. Verify all
individual jobs, fetched bytes, signatures and each version's LICENSE, then
independently run the existing nonpublishing admission path against that exact
current-head run. A subsequent publication request needs separate authorization.
No such operational event is part of the readiness PRs.

The Catalog pg_permissions evaluator deliberately remains diagnostic-only:
`CANDIDATE_ONLY`, 0/7, `publishDecision=DENY`, `publicGetDecision=DENY`. Neither
static configuration nor the offline tests below promote its gates. Public GET
remains DENY regardless of gate count. Do not restore boolean evidence input or
add another acceptance layer to reuse this source route.

Existing offline suites cover central source authentication and admission:

```sh
python tests/test-chat-signed-main-source.py
python tests/test-publisher-owner-source-admission.py
python tests/test-owner-source-publish-policy.py
python tests/test-publisher-owner-source-publish-request.py
python tests/test-owner-source-publisher-inprocess.py
python tests/test-owner-source-formal-publisher.py
```

The passenger regression in the admission suite executes the same `admit()`,
`audit()`, proof-statement checks and `join()` for both SQL-only identities with
PG15–18. Only transport/cryptographic verification is mocked; synthetic fixtures
are never evidence of real signatures or runtime admission. It also rejects a
stale original receipt when it differs from the fresh audit.
