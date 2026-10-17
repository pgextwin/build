# Issue #75: inert Windows KB/MSU conditional source inventory

This is a follow-up to merged build PR #124 and Issue #75 comment #6235256672.
Historical Chocolatey source includes OS-specific or dynamic PowerShell branches.
The prior eight `.nupkg` SHA256 proofs establish archive bytes, not the
installer URLs that a runner might select or execute.

## Bounded read-only witness

`scripts/issue-75-kb-conditional-inert.py --mode observe` runs only from the
`issue-75-kb-conditional-inert` pull request in the isolated
`issue75_kb_inert` Windows job with `contents:read`, checkout credential
persistence disabled, no repository secret, no write permission and no artifact.

It retrieves each of eight allowlisted historical Chocolatey `.nupkg` files
twice from the existing strict HTTPS source/redirect allowlist, compares both
downloads and checks each archive against its previously observed **whole-file
SHA256**. It reuses the existing archive/nuspec/path-traversal checks and
extracts only `.ps1` text. It never invokes PowerShell, Chocolatey, EXE, MSU,
package installers or publish operations.

For every script it records its SHA256, line-numbered literal URL candidates,
URL/checksum assignment candidates, OS hashtable labels, conditional statement
counts and download helper mentions. A literal can appear in a comment, an
inactive OS branch or an indirect helper invocation. This is lexical inventory:
there is **no** PowerShell interpretation, no verified URL/checksum pairing,
no authenticated running OS branch, no MSU download and no guarantee that
literal extraction detects every dynamic network dependency. Dynamic/indirect
behavior and mismatched or missing checksums remain UNKNOWN/DENY.

Prior original-byte sources: successful Runs 39039052934 and 39039490483;
historical Run 39039716020 was parent FAILURE (its successful individual job
is not counted as a successful parent). The additional three third-level
nupkg originals were independently re-observed in successful PR Run
39041869619. All eight immutable archive SHA256 values are enforced in code;
mutation or download disagreement terminates with exit 2.

## Non-publishing acceptance boundary

The required App15368 resolver executes hostile offline fixtures and the
static denied-mode guard for every PR/main push. The PR-only Windows job may
add verified **archive-byte** and source-characterization evidence once its
own exact-head run completes successfully. A success never proves KB/MSU
payload bytes, actual runner dependency SHA closure, production Signer/Writer
credential isolation, signed Publisher positive prewrite, or schema v2 recovery.

GO B/G4/G5 remain **NO-GO**; P1 65/70, independent source 40/40,
historical plpgsql_check PG14–18 five DENY, P1 BLOCKED/P2 NO-GO,
formal Release/distribution DENY. Signer and Publisher production pins,
plpgsql_check PR #29, `promote.yml`, secrets, budget, branch protection,
tags and release publication are out of scope.

Follow-up: use the source inventory to prioritize explicit OS/architecture
paths and separately measure MSU original bytes (only if bounded and pinned).
No selected conditional path or dynamic runtime dependency is accepted on
lexical source evidence alone.
